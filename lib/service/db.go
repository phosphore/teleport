/*
Copyright 2020 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package service

import (
	"fmt"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/cache"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/reversetunnel"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/srv/db"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
)

func (process *TeleportProcess) initDatabases() {
	if len(process.Config.Databases.Databases) == 0 {
		return
	}
	process.registerWithAuthServer(teleport.RoleDatabase, DatabasesIdentityEvent)
	process.RegisterCriticalFunc("db.init", process.initDatabaseService)
}

func (process *TeleportProcess) initDatabaseService() error {
	log := logrus.WithField(trace.Component, teleport.Component(
		teleport.ComponentDB, process.id))

	eventsCh := make(chan Event)
	process.WaitForEvent(process.ExitContext(), DatabasesIdentityEvent, eventsCh)

	var event Event
	select {
	case event = <-eventsCh:
		log.Debugf("Received event %q.", event.Name)
	case <-process.ExitContext().Done():
		log.Debug("Process is exiting.")
		return nil
	}

	conn, ok := (event.Payload).(*Connector)
	if !ok {
		return trace.BadParameter("unsupported event payload type %q", event.Payload)
	}

	var tunnelAddr string
	if conn.TunnelProxy() != "" {
		tunnelAddr = conn.TunnelProxy()
	} else {
		if tunnelAddr, ok = process.singleProcessMode(); !ok {
			return trace.BadParameter("failed to find reverse tunnel address, " +
				"if running in a single-process mode, make sure auth_service, " +
				"proxy_service, and db_service are all enabled")
		}
	}

	accessPoint, err := process.newLocalCache(conn.Client, cache.ForDatabases, []string{teleport.ComponentDB})
	if err != nil {
		return trace.Wrap(err)
	}

	// Start uploader that will scan a path on disk and upload completed
	// sessions to the Auth Server.
	// TODO(r0mant): Should this run once per process?
	err = process.initUploaderService(accessPoint, conn.Client)
	if err != nil {
		return trace.Wrap(err)
	}

	// Create database server for each of the proxied databases.
	var databaseServers []services.DatabaseServer
	for _, db := range process.Config.Databases.Databases {
		databaseServers = append(databaseServers, services.NewDatabaseServerV2(
			fmt.Sprintf("%v-%v", process.Config.HostUUID, db.Name),
			db.StaticLabels,
			services.DatabaseServerSpecV2{
				Name:          db.Name,
				Description:   db.Description,
				Protocol:      db.Protocol,
				URI:           db.URI,
				CACert:        db.CACert,
				AWS:           services.AWS{Region: db.AWS.Region},
				DynamicLabels: services.LabelsToV2(db.DynamicLabels),
				Version:       teleport.Version,
				Hostname:      process.Config.Hostname,
				HostID:        process.Config.HostUUID,
			}))
	}

	authorizer, err := auth.NewAuthorizer(conn.Client, conn.Client, conn.Client)
	if err != nil {
		return trace.Wrap(err)
	}
	tlsConfig, err := conn.ServerIdentity.TLSConfig(nil)
	if err != nil {
		return trace.Wrap(err)
	}

	asyncEmitter, err := process.newAsyncEmitter(conn.Client)
	if err != nil {
		return trace.Wrap(err)
	}
	streamer, err := events.NewCheckingStreamer(events.CheckingStreamerConfig{
		Inner: conn.Client,
		Clock: process.Clock,
	})
	if err != nil {
		return trace.Wrap(err)
	}

	// Create and start the database service.
	dbService, err := db.New(process.ExitContext(), db.Config{
		DataDir:     process.Config.DataDir,
		AuthClient:  conn.Client,
		AccessPoint: accessPoint,
		StreamEmitter: &events.StreamerAndEmitter{
			Emitter:  asyncEmitter,
			Streamer: streamer,
		},
		Authorizer:   authorizer,
		TLSConfig:    tlsConfig,
		CipherSuites: process.Config.CipherSuites,
		GetRotation:  process.getRotation,
		Servers:      databaseServers,
		OnHeartbeat: func(err error) {
			if err != nil {
				process.BroadcastEvent(Event{Name: TeleportDegradedEvent, Payload: teleport.ComponentDB})
			} else {
				process.BroadcastEvent(Event{Name: TeleportOKEvent, Payload: teleport.ComponentDB})
			}
		},
	})
	if err != nil {
		return trace.Wrap(err)
	}
	if err := dbService.Start(); err != nil {
		return trace.Wrap(err)
	}

	// Create and start the agent pool.
	agentPool, err := reversetunnel.NewAgentPool(process.ExitContext(),
		reversetunnel.AgentPoolConfig{
			Component:   teleport.ComponentDB,
			HostUUID:    conn.ServerIdentity.ID.HostUUID,
			ProxyAddr:   tunnelAddr,
			Client:      conn.Client,
			Server:      dbService,
			AccessPoint: conn.Client,
			HostSigner:  conn.ServerIdentity.KeySigner,
			Cluster:     conn.ServerIdentity.Cert.Extensions[utils.CertExtensionAuthority],
		})
	if err != nil {
		return trace.Wrap(err)
	}
	if err := agentPool.Start(); err != nil {
		return trace.Wrap(err)
	}

	process.BroadcastEvent(Event{Name: DatabasesReady, Payload: nil})
	log.Info("Database service has successfully started.")

	// Block and wait while the server and agent pool are running.
	if err := dbService.Wait(); err != nil {
		return trace.Wrap(err)
	}
	agentPool.Wait()

	// Execute this when the process running database proxy service exits.
	process.onExit("db.stop", func(payload interface{}) {
		log.Info("Shutting down.")
		if dbService != nil {
			warnOnErr(dbService.Close())
		}
		if agentPool != nil {
			agentPool.Stop()
		}
		log.Info("Exited.")
	})

	return nil
}
