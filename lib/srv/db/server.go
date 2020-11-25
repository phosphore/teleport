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
	"crypto/tls"
	"net"
	"sync"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/labels"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/srv"
	"github.com/gravitational/teleport/lib/srv/db/postgres"
	"github.com/gravitational/teleport/lib/srv/db/session"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/aws/aws-sdk-go/aws/credentials"
	awssession "github.com/aws/aws-sdk-go/aws/session"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/pborman/uuid"
	"github.com/sirupsen/logrus"
)

// TODO(r0mant): Redefined in srv/app/server.go.
type RotationGetter func(role teleport.Role) (*services.Rotation, error)

// Config is the configuration for an database proxy server.
type Config struct {
	// Clock used to control time.
	Clock clockwork.Clock
	// DataDir is the path to the data directory for the server.
	DataDir string
	// AuthClient is a client directly connected to the Auth server.
	AuthClient *auth.Client
	// AccessPoint is a caching client connected to the Auth Server.
	AccessPoint auth.AccessPoint
	// StreamEmitter is a non-blocking audit events emitter.
	StreamEmitter events.StreamEmitter
	// TLSConfig is the *tls.Config for this server.
	TLSConfig *tls.Config
	// CipherSuites is the list of TLS cipher suites that have been configured
	// for this process.
	CipherSuites []uint16
	// Authorizer is used to authorize requests coming from proxy.
	Authorizer auth.Authorizer
	// GetRotation returns the certificate rotation state.
	GetRotation RotationGetter
	// Servers contains a list of database servers this service proxies.
	Servers []services.DatabaseServer
	// Credentials are credentials to AWS API.
	Credentials *credentials.Credentials
	// OnHeartbeat is called after every heartbeat. Used to update process state.
	OnHeartbeat func(error)
}

// CheckAndSetDefaults makes sure the configuration has the minimum required
// to function.
func (c *Config) CheckAndSetDefaults() error {
	if c.Clock == nil {
		c.Clock = clockwork.NewRealClock()
	}
	if c.DataDir == "" {
		return trace.BadParameter("data dir missing")
	}
	if c.AuthClient == nil {
		return trace.BadParameter("auth client log missing")
	}
	if c.AccessPoint == nil {
		return trace.BadParameter("access point missing")
	}
	if c.StreamEmitter == nil {
		return trace.BadParameter("stream emitter missing")
	}
	if c.TLSConfig == nil {
		return trace.BadParameter("tls config missing")
	}
	if len(c.CipherSuites) == 0 {
		return trace.BadParameter("cipersuites missing")
	}
	if c.Authorizer == nil {
		return trace.BadParameter("authorizer missing")
	}
	if c.GetRotation == nil {
		return trace.BadParameter("rotation getter missing")
	}
	if len(c.Servers) == 0 {
		return trace.BadParameter("database servers missing")
	}
	if c.OnHeartbeat == nil {
		return trace.BadParameter("heartbeat missing")
	}
	if c.Credentials == nil {
		session, err := awssession.NewSessionWithOptions(awssession.Options{
			SharedConfigState: awssession.SharedConfigEnable,
		})
		if err != nil {
			return trace.Wrap(err)
		}
		c.Credentials = session.Config.Credentials
	}
	return nil
}

// Server is an application server. It authenticates requests from the web
// proxy and forwards them to internal applications.
type Server struct {
	// Config is the database server configuration.
	Config
	// closeContext is used to indicate the server is closing.
	closeContext context.Context
	// closeFunc is the cancel function of the close context.
	closeFunc context.CancelFunc
	// mu protects access to the server info.
	mu sync.RWMutex
	// middleware extracts identity from client certificates.
	middleware *auth.Middleware
	// dynamicLabels contains dynamic labels for database servers.
	dynamicLabels map[string]*labels.Dynamic
	// heartbeats holds hearbeats for database servers.
	heartbeats map[string]*srv.Heartbeat
	// rdsCACerts contains loaded RDS root certificates for required regions.
	rdsCACerts map[string][]byte
	// Entry is used for logging.
	*logrus.Entry
}

// New returns a new application server.
func New(ctx context.Context, config Config) (*Server, error) {
	err := config.CheckAndSetDefaults()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	localCtx, cancel := context.WithCancel(ctx)
	server := &Server{
		Config:        config,
		Entry:         logrus.WithField(trace.Component, teleport.ComponentDB),
		closeContext:  localCtx,
		closeFunc:     cancel,
		dynamicLabels: make(map[string]*labels.Dynamic),
		heartbeats:    make(map[string]*srv.Heartbeat),
		rdsCACerts:    make(map[string][]byte),
		middleware: &auth.Middleware{
			AccessPoint:   config.AccessPoint,
			AcceptedUsage: []string{teleport.UsageDatabaseOnly},
		},
	}

	// Update TLS config to require client certificate.
	server.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
	server.TLSConfig.GetConfigForClient = getConfigForClient(
		server.TLSConfig, server.AccessPoint, server.Entry)

	// Perform various initialization actions on each proxied database, like
	// starting up dynamic labels and loading root certs for RDS dbs.
	for _, db := range server.Servers {
		if err := server.initDatabaseServer(localCtx, db); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	return server, nil
}

func (s *Server) initDatabaseServer(ctx context.Context, server services.DatabaseServer) error {
	if err := s.initDynamicLabels(ctx, server); err != nil {
		return trace.Wrap(err)
	}
	if err := s.initHeartbeat(ctx, server); err != nil {
		return trace.Wrap(err)
	}
	if err := s.initRDSRootCert(ctx, server); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func (s *Server) initDynamicLabels(ctx context.Context, server services.DatabaseServer) error {
	if len(server.GetDynamicLabels()) == 0 {
		return nil // Nothing to do.
	}
	dynamic, err := labels.NewDynamic(ctx, &labels.DynamicConfig{
		Labels: server.GetDynamicLabels(),
		Log:    s.Entry,
	})
	if err != nil {
		return trace.Wrap(err)
	}
	dynamic.Sync()
	s.dynamicLabels[server.GetName()] = dynamic
	return nil
}

func (s *Server) initHeartbeat(ctx context.Context, server services.DatabaseServer) error {
	heartbeat, err := srv.NewHeartbeat(srv.HeartbeatConfig{
		Context:   s.closeContext,
		Component: teleport.ComponentDB,
		Mode:      srv.HeartbeatModeDB,
		Announcer: s.AccessPoint,
		GetServerInfo: func() (services.Resource, error) {
			// Update dynamic labels.
			if labels, ok := s.dynamicLabels[server.GetName()]; ok {
				server.SetDynamicLabels(labels.Get())
			}
			// Update CA rotation state.
			rotation, err := s.GetRotation(teleport.RoleDatabase)
			if err != nil && !trace.IsNotFound(err) {
				s.WithError(err).Warn("Failed to get rotation state.")
			} else {
				server.SetRotation(*rotation)
			}
			// Update TTL.
			server.SetTTL(s.Clock, defaults.ServerAnnounceTTL)
			return server, nil
		},
		KeepAlivePeriod: defaults.ServerKeepAliveTTL,
		AnnouncePeriod:  defaults.ServerAnnounceTTL/2 + utils.RandomDuration(defaults.ServerAnnounceTTL/10),
		CheckPeriod:     defaults.HeartbeatCheckPeriod,
		ServerTTL:       defaults.ServerAnnounceTTL,
		OnHeartbeat:     s.OnHeartbeat,
	})
	if err != nil {
		return trace.Wrap(err)
	}
	s.heartbeats[server.GetName()] = heartbeat
	return nil
}

// Start starts heartbeating the presence of service.Databases that this
// server is proxying along with any dynamic labels.
func (s *Server) Start() error {
	for _, dynamicLabel := range s.dynamicLabels {
		go dynamicLabel.Start()
	}
	for _, heartbeat := range s.heartbeats {
		go heartbeat.Run()
	}
	return nil
}

// Close will shut the server down and unblock any resources.
func (s *Server) Close() error {
	// Stop dynamic label updates.
	for _, dynamicLabel := range s.dynamicLabels {
		dynamicLabel.Close()
	}
	// Signal to all goroutines to stop.
	s.closeFunc()
	// Stop the heartbeats.
	var errors []error
	for _, heartbeat := range s.heartbeats {
		errors = append(errors, heartbeat.Close())
	}
	return trace.NewAggregate(errors...)
}

// Wait will block while the server is running.
func (s *Server) Wait() error {
	<-s.closeContext.Done()
	return s.closeContext.Err()
}

// HandleConnection accepts the connection coming over reverse tunnel,
// upgrades it to TLS, extracts identity information from it, performs
// authorization and dispatches to the appropriate database engine.
func (s *Server) HandleConnection(conn net.Conn) {
	log := s.WithField("addr", conn.RemoteAddr())
	log.Debug("Accepted connection.", conn.RemoteAddr())
	defer conn.Close()
	// Upgrade the connection to TLS since the other side of the reverse
	// tunnel connection (proxy) will initiate a handshake.
	tlsConn := tls.Server(conn, s.TLSConfig)
	// Perform the hanshake explicitly, normally it should be performed
	// on the first read/write but when the connection is passed over
	// reverse tunnel it doesn't happen for some reason.
	err := tlsConn.Handshake()
	if err != nil {
		log.WithError(err).Error("Failed to perform TLS handshake.")
		return
	}
	// Now that the handshake has completed and the client has sent us a
	// certificate, extract identity information from it.
	ctx, err := s.middleware.WrapContext(context.Background(), tlsConn)
	if err != nil {
		log.WithError(err).Error("Failed to extract identity from connection.")
		return
	}
	// Dispatch the connection for processing by an appropriate database
	// service.
	err = s.handleConnection(ctx, tlsConn)
	if err != nil {
		log.WithError(err).Error("Failed to handle connection.")
		return
	}
}

func (s *Server) handleConnection(ctx context.Context, conn net.Conn) error {
	sessionCtx, err := s.authorize(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	streamWriter, err := s.newStreamWriter(sessionCtx)
	if err != nil {
		return trace.Wrap(err)
	}
	defer func() {
		// Closing the stream writer is needed to flush all recorded data
		// and trigger upload. Do it in a goroutine since depending on
		// session size it can take a while and we don't want to block
		// the client.
		go func() {
			// Use the server closing context to make sure that upload
			// continues beyond the session lifetime.
			err := streamWriter.Close(s.closeContext)
			if err != nil {
				sessionCtx.Log.WithError(err).Warn("Failed to close stream writer.")
			}
		}()
	}()
	engine, err := s.dispatch(sessionCtx, streamWriter)
	if err != nil {
		return trace.Wrap(err)
	}
	err = engine.HandleConnection(ctx, sessionCtx, conn)
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// DatabaseEngine defines an interface for specific database protocol engine
// such as postgres or mysql.
type DatabaseEngine interface {
	// HandleConnection takes the connection from the proxy and starts
	// proxying it to the particular database instance.
	HandleConnection(context.Context, *session.Context, net.Conn) error
}

// dispatch returns an appropriate database engine for the session.
func (s *Server) dispatch(sessionCtx *session.Context, streamWriter events.StreamWriter) (DatabaseEngine, error) {
	switch sessionCtx.Server.GetProtocol() {
	case defaults.ProtocolPostgres:
		return &postgres.Engine{
			AuthClient:     s.AuthClient,
			Credentials:    s.Credentials,
			RDSCACerts:     s.rdsCACerts,
			OnSessionStart: s.emitSessionStartEventFn(streamWriter),
			OnSessionEnd:   s.emitSessionEndEventFn(streamWriter),
			OnQuery:        s.emitQueryEventFn(streamWriter),
			Clock:          s.Clock,
			Log:            sessionCtx.Log,
		}, nil
	}
	return nil, trace.BadParameter("unsupported database procotol %q",
		sessionCtx.Server.GetProtocol())
}

func (s *Server) authorize(ctx context.Context) (*session.Context, error) {
	// Only allow local and remote identities to proxy to a database.
	userType := ctx.Value(auth.ContextUser)
	switch userType.(type) {
	case auth.LocalUser, auth.RemoteUser:
	default:
		return nil, trace.BadParameter("invalid identity: %T", userType)
	}
	// Extract authorizing context and identity of the user from the request.
	authContext, err := s.Authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	identity := authContext.Identity.GetIdentity()
	s.Debugf("Client identity: %#v.", identity)
	// Fetch the requested database server.
	var server services.DatabaseServer
	for _, s := range s.Servers {
		if s.GetDatabaseName() == identity.RouteToDatabase.ServiceName {
			server = s
		}
	}
	s.Debugf("Will connect to database %q at %v.", server.GetDatabaseName(),
		server.GetURI())
	id := uuid.New()
	return &session.Context{
		ID:       id,
		Server:   server,
		Identity: identity,
		Checker:  authContext.Checker,
		Log: s.WithFields(logrus.Fields{
			"id": id,
			"db": server.GetDatabaseName(),
		}),
	}, nil
}
