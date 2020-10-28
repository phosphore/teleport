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
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/labels"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/srv"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
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
	// TLSConfig is the *tls.Config for this server.
	TLSConfig *tls.Config
	// CipherSuites is the list of TLS cipher suites that have been configured
	// for this process.
	CipherSuites []uint16
	// Authorizer is used to authorize requests coming from proxy.
	Authorizer auth.Authorizer
	// GetRotation returns the certificate rotation state.
	GetRotation RotationGetter
	// Server contains the list of databaes that will be proxied.
	Server services.Server
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
	if c.Server == nil {
		return trace.BadParameter("server missing")
	}
	if c.OnHeartbeat == nil {
		return trace.BadParameter("heartbeat missing")
	}
	if c.Credentials == nil {
		session, err := session.NewSessionWithOptions(session.Options{
			SharedConfigState: session.SharedConfigEnable,
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
	// heartbeat holds the server heartbeat.
	heartbeat *srv.Heartbeat
	// dynamicLabels are command labels updated by the server.
	dynamicLabels map[string]*labels.Dynamic
	// rdsCACerts contains loaded RDS root certificates for required regions.
	rdsCACerts map[string][]byte
	// Entry is used for logging.
	*logrus.Entry
}

// New returns a new application server.
func New(ctx context.Context, config Config) (*Server, error) {
	if err := config.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	localCtx, cancel := context.WithCancel(ctx)
	server := &Server{
		Config:        config,
		Entry:         logrus.WithField(trace.Component, teleport.ComponentDB),
		closeContext:  localCtx,
		closeFunc:     cancel,
		dynamicLabels: make(map[string]*labels.Dynamic),
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
	for _, db := range server.Server.GetDatabases() {
		if err := server.initDatabase(localCtx, db); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	// Create heartbeat loop so databases keep sending presence to auth server.
	heartbeat, err := srv.NewHeartbeat(srv.HeartbeatConfig{
		Mode:            srv.HeartbeatModeDB,
		Context:         server.closeContext,
		Component:       teleport.ComponentDB,
		Announcer:       config.AccessPoint,
		GetServerInfo:   server.GetServerInfo,
		KeepAlivePeriod: defaults.ServerKeepAliveTTL,
		AnnouncePeriod:  defaults.ServerAnnounceTTL/2 + utils.RandomDuration(defaults.ServerAnnounceTTL/10),
		CheckPeriod:     defaults.HeartbeatCheckPeriod,
		ServerTTL:       defaults.ServerAnnounceTTL,
		OnHeartbeat:     config.OnHeartbeat,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	server.heartbeat = heartbeat

	return server, nil
}

func (s *Server) initDatabase(ctx context.Context, db *services.Database) error {
	if err := s.initDatabaseDynamicLabels(ctx, db); err != nil {
		return trace.Wrap(err)
	}
	if err := s.initRDSRootCert(ctx, db); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func (s *Server) initDatabaseDynamicLabels(ctx context.Context, db *services.Database) error {
	if len(db.DynamicLabels) == 0 {
		return nil // Nothing to do.
	}
	dynamic, err := labels.NewDynamic(ctx, &labels.DynamicConfig{
		Labels: services.V2ToLabels(db.DynamicLabels),
		Log:    s.Entry,
	})
	if err != nil {
		return trace.Wrap(err)
	}
	dynamic.Sync()
	s.dynamicLabels[db.Name] = dynamic
	return nil
}

// GetServerInfo returns a services.Server representing the database proxy.
func (s *Server) GetServerInfo() (services.Server, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updateDynamicLabels()
	s.Server.SetTTL(s.Clock, defaults.ServerAnnounceTTL)
	s.updateRotationState()
	return s.Server, nil
}

// updateDynamicLabels updates dynamic labels on the database services proxied
// by this server to their most recent values.
func (s *Server) updateDynamicLabels() {
	databases := s.Server.GetDatabases()
	for i, db := range databases {
		if labels, ok := s.dynamicLabels[db.Name]; ok {
			databases[i].DynamicLabels = services.LabelsToV2(labels.Get())
		}
	}
	s.Server.SetDatabases(databases)
}

// updateRotationState updates the server's CA rotation state.
func (s *Server) updateRotationState() {
	rotation, err := s.GetRotation(teleport.RoleDatabase)
	if err != nil && !trace.IsNotFound(err) {
		s.WithError(err).Warn("Failed to get rotation state.")
	} else {
		s.Server.SetRotation(*rotation)
	}
}

// Start starts heartbeating the presence of service.Databases that this
// server is proxying along with any dynamic labels.
func (s *Server) Start() error {
	for _, dynamicLabel := range s.dynamicLabels {
		go dynamicLabel.Start()
	}
	return s.heartbeat.Run()
}

// Close will shut the server down and unblock any resources.
func (s *Server) Close() error {
	// Stop dynamic label updates.
	for _, dynamicLabel := range s.dynamicLabels {
		dynamicLabel.Close()
	}
	// Signal to all goroutines to stop.
	s.closeFunc()
	// Stop the heartbeat
	return s.heartbeat.Close()
}

// Wait will block while the server is running.
func (s *Server) Wait() error {
	<-s.closeContext.Done()
	return s.closeContext.Err()
}

// ForceHeartbeat is used in tests to force updating of services.Server.
func (s *Server) ForceHeartbeat() error {
	err := s.heartbeat.ForceSend(time.Second)
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// HandleConnection accepts the connection coming over reverse tunnel,
// upgrades it to TLS, extracts identity information from it, performs
// authorization and dispatches to the appropriate database engine.
func (s *Server) HandleConnection(conn net.Conn) {
	s.Debugf("Accepted connection from %v.", conn.RemoteAddr())
	// Upgrade the connection to TLS since the other side of the reverse
	// tunnel connection (proxy) will initiate a handshake.
	tlsConn := tls.Server(conn, s.TLSConfig)
	// Perform the hanshake explicitly, normally it should be performed
	// on the first read/write but when the connection is passed over
	// reverse tunnel it doesn't happen for some reason.
	err := tlsConn.Handshake()
	if err != nil {
		s.WithError(err).Error("Failed to perform TLS handshake.")
		return
	}
	// Now that the handshake has completed and the client has sent us a
	// certificate, extract identity information from it.
	ctx, err := s.middleware.WrapContext(context.TODO(), tlsConn)
	if err != nil {
		s.WithError(err).Error("Failed to extract identity from connection.")
		return
	}
	// Dispatch the connection for processing by an appropriate database
	// service.
	err = s.handleConnection(ctx, tlsConn)
	if err != nil {
		s.WithError(err).Error("Failed to handle connection.")
		return
	}
}

func (s *Server) handleConnection(ctx context.Context, conn net.Conn) error {
	sessionCtx, err := s.authorize(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	streamWriter, err := s.newStreamWriter(sessionCtx.id)
	if err != nil {
		return trace.Wrap(err)
	}
	engine, err := s.dispatch(sessionCtx, streamWriter)
	if err != nil {
		return trace.Wrap(err)
	}
	err = engine.handleConnection(ctx, sessionCtx, conn)
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// dispatch returns an appropriate database engine for the session.
func (s *Server) dispatch(sessionCtx *sessionContext, streamWriter events.StreamWriter) (databaseEngine, error) {
	switch sessionCtx.db.Protocol {
	case defaults.ProtocolPostgres:
		return &postgresEngine{
			authClient:     s.AuthClient,
			credentials:    s.Credentials,
			rdsCACerts:     s.rdsCACerts,
			onSessionStart: s.emitSessionStartEventFn(streamWriter),
			onSessionEnd:   s.emitSessionEndEventFn(streamWriter),
			onQuery:        s.emitQueryEventFn(streamWriter),
			clock:          s.Clock,
			FieldLogger: s.Entry.WithFields(logrus.Fields{
				"id": sessionCtx.id,
				"db": sessionCtx.db.Name,
			}),
		}, nil
	}
	return nil, trace.BadParameter("unsupported database procotol %q",
		sessionCtx.db.Protocol)
}

func (s *Server) authorize(ctx context.Context) (*sessionContext, error) {
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
	// Fetch the requested database.
	var db *services.Database
	for _, d := range s.Server.GetDatabases() {
		if d.Name == identity.RouteToDatabase.DatabaseName {
			db = d
		}
	}
	s.Debugf("Will connect to database %q at %v.", db.Name, db.URI)
	return &sessionContext{
		id:       uuid.New(),
		db:       db,
		identity: identity,
		checker:  authContext.Checker,
	}, nil
}
