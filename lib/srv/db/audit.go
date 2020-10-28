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

package db

import (
	"context"
	"path/filepath"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/events/filesessions"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/session"

	"github.com/gravitational/trace"
)

// newStreamWriter creates a streamer that will be used to stream the
// requests that occur within this session to the audit log.
func (s *Server) newStreamWriter(sessionID string) (events.StreamWriter, error) {
	clusterConfig, err := s.AccessPoint.GetClusterConfig()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	// Create a sync or async streamer depending on configuration of cluster.
	streamer, err := s.newStreamer(s.closeContext, sessionID, clusterConfig)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	// Audit stream is using server context, not session context,
	// to make sure that session is uploaded even after it is closed
	return events.NewAuditWriter(events.AuditWriterConfig{
		Context:      s.closeContext,
		Streamer:     streamer,
		Clock:        s.Clock,
		SessionID:    session.ID(sessionID),
		Namespace:    defaults.Namespace,
		ServerID:     s.Server.GetName(),
		RecordOutput: clusterConfig.GetSessionRecording() != services.RecordOff,
		Component:    teleport.ComponentApp,
	})
}

// newStreamer returns sync or async streamer based on the configuration
// of the server and the session, sync streamer sends the events
// directly to the auth server and blocks if the events can not be received,
// async streamer buffers the events to disk and uploads the events later
func (s *Server) newStreamer(ctx context.Context, sessionID string, clusterConfig services.ClusterConfig) (events.Streamer, error) {
	mode := clusterConfig.GetSessionRecording()
	if services.IsRecordSync(mode) {
		s.Debugf("Using sync streamer for session %v.", sessionID)
		return s.AuthClient, nil
	}
	s.Debugf("Using async streamer for session %v.", sessionID)
	uploadDir := filepath.Join(
		s.DataDir, teleport.LogsDir, teleport.ComponentUpload,
		events.StreamingLogsDir, defaults.Namespace)
	fileStreamer, err := filesessions.NewStreamer(uploadDir)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return fileStreamer, nil
}

// emitSessionStartEventFn returns function that uses the provided emitter to
// emit an audit event when database session starts.
func (s *Server) emitSessionStartEventFn(streamWriter events.StreamWriter) func(sessionContext) error {
	return func(session sessionContext) error {
		// TODO(r0mant): Use streamWriter.
		return s.AuthClient.EmitAuditEvent(s.closeContext, &events.DatabaseSessionStart{
			Metadata: events.Metadata{
				Type: events.DatabaseSessionStartEvent,
				Code: events.DatabaseSessionStartCode,
			},
			ServerMetadata: events.ServerMetadata{
				ServerID:        s.Server.GetName(),
				ServerNamespace: defaults.Namespace,
			},
			UserMetadata: events.UserMetadata{
				User: session.identity.Username,
			},
			SessionMetadata: events.SessionMetadata{
				SessionID: session.id,
			},
			DatabaseMetadata: &events.DatabaseMetadata{
				DBName:     session.db.Name,
				DBProtocol: session.db.Protocol,
				DBEndpoint: session.db.URI,
				DBDatabase: session.dbName,
				DBUser:     session.dbUser,
			},
		})
	}
}

// emitSessionEndEventFn returns function that uses the provided emitter to
// emit an audit event when database session ends.
func (s *Server) emitSessionEndEventFn(streamWriter events.StreamWriter) func(sessionContext) error {
	return func(session sessionContext) error {
		// TODO(r0mant): Use streamWriter.
		return s.AuthClient.EmitAuditEvent(s.closeContext, &events.DatabaseSessionEnd{
			Metadata: events.Metadata{
				Type: events.DatabaseSessionEndEvent,
				Code: events.DatabaseSessionEndCode,
			},
			UserMetadata: events.UserMetadata{
				User: session.identity.Username,
			},
			SessionMetadata: events.SessionMetadata{
				SessionID: session.id,
			},
			DatabaseMetadata: &events.DatabaseMetadata{
				DBName:     session.db.Name,
				DBProtocol: session.db.Protocol,
				DBEndpoint: session.db.URI,
				DBDatabase: session.dbName,
				DBUser:     session.dbUser,
			},
		})
	}
}

// emitQueryEventFn returns function that uses the provided emitter to emit
// an audit event when a database query is executed.
func (s *Server) emitQueryEventFn(streamWriter events.StreamWriter) func(sessionContext, string) error {
	return func(session sessionContext, query string) error {
		// TODO(r0mant): Use streamWriter.
		return s.AuthClient.EmitAuditEvent(s.closeContext, &events.DatabaseQuery{
			Metadata: events.Metadata{
				Type: events.DatabaseQueryEvent,
				Code: events.DatabaseQueryCode,
			},
			UserMetadata: events.UserMetadata{
				User: session.identity.Username,
			},
			SessionMetadata: events.SessionMetadata{
				SessionID: session.id,
			},
			DatabaseMetadata: &events.DatabaseMetadata{
				DBName:     session.db.Name,
				DBProtocol: session.db.Protocol,
				DBEndpoint: session.db.URI,
				DBDatabase: session.dbName,
				DBUser:     session.dbUser,
			},
			Query: query,
		})
	}
}
