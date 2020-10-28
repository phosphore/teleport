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
	"crypto/x509"
	"fmt"
	"net"

	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/native"
	"github.com/gravitational/teleport/lib/auth/proto"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/multiplexer"
	"github.com/gravitational/teleport/lib/reversetunnel"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
)

// ProxyServer is responsible to accepting connections coming from the
// database clients (via a multiplexer) and dispatching them to the
// appropriate database services over reverse tunnel.
type ProxyServer struct {
	// ProxyServerConfig is the proxy configuration.
	ProxyServerConfig
	// FieldLogger is used for logging.
	logrus.FieldLogger
	// middleware extracts identity information from client certificates.
	middleware *auth.Middleware
	// closeCtx is closed when the process shuts down.
	closeCtx context.Context
}

// ProxyServerConfig is the proxy configuration.
type ProxyServerConfig struct {
	// AuthClient is the authenticated client to the auth server.
	AuthClient *auth.Client
	// AccessPoint is the caching client connected to the auth server.
	AccessPoint auth.AccessPoint
	// Authorizer is responsible for authorizing user identities.
	Authorizer auth.Authorizer
	// Tunnel is the reverse tunnel server.
	Tunnel reversetunnel.Server
	// TLSConfig is the proxy server TLS configuration.
	TLSConfig *tls.Config
}

// CheckAndSetDefaults validates the config and sets default values.
func (c *ProxyServerConfig) CheckAndSetDefaults() error {
	if c.AccessPoint == nil {
		return trace.BadParameter("missing AccessPoint")
	}
	if c.AuthClient == nil {
		return trace.BadParameter("missing AuthClient")
	}
	if c.Authorizer == nil {
		return trace.BadParameter("missing Authorizer")
	}
	if c.Tunnel == nil {
		return trace.BadParameter("missing Tunnel")
	}
	if c.TLSConfig == nil {
		return trace.BadParameter("missing TLSConfig")
	}
	return nil
}

// NewProxyServer creates a new instance of the database proxy server.
func NewProxyServer(ctx context.Context, config ProxyServerConfig) (*ProxyServer, error) {
	if err := config.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	server := &ProxyServer{
		ProxyServerConfig: config,
		FieldLogger:       logrus.WithField(trace.Component, "db:proxy"),
		middleware: &auth.Middleware{
			AccessPoint: config.AccessPoint,
		},
		closeCtx: ctx,
	}
	// TODO(r0mant): Copy TLS config?
	server.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
	server.TLSConfig.GetConfigForClient = getConfigForClient(
		server.TLSConfig, server.AccessPoint, server.FieldLogger)
	return server, nil
}

// Serve starts accepting database connections from the provided listener.
func (s *ProxyServer) Serve(listener net.Listener) error {
	defer s.Debug("Exited.")
	for {
		// Accept the connection from the database client, such as psql.
		// The connection is expected to come through via multiplexer.
		clientConn, err := listener.Accept()
		if err != nil {
			s.WithError(err).Error("Failed to accept connection.")
			continue
		}
		// The multiplexed connection contains information about detected
		// protocol so dispatch to the appropriate proxy.
		proxy, err := s.dispatch(clientConn)
		if err != nil {
			s.WithError(err).Error("Failed to dispatch connection.")
			continue
		}
		// Let the appropriate proxy handle the connection and go back
		// to listening.
		go func() {
			defer func() {
				err := clientConn.Close()
				if err != nil {
					s.WithError(err).Error("Failed to close connection.")
				}
			}()
			err := proxy.handleConnection(s.closeCtx, clientConn)
			if err != nil {
				s.WithError(err).Error("Failed to handle connection.")
			}
		}()
	}
}

// dispatch dispatches the connection to appropriate database proxy.
func (s *ProxyServer) dispatch(clientConn net.Conn) (databaseProxy, error) {
	muxConn, ok := clientConn.(*multiplexer.Conn)
	if !ok {
		return nil, trace.BadParameter("expected multiplexer connection, got %T", clientConn)
	}
	switch muxConn.Protocol() {
	case multiplexer.ProtoPostgres:
		s.Debugf("Accepted postgres connection from %v.", muxConn.RemoteAddr())
		return &postgresProxy{
			tlsConfig:     s.TLSConfig,
			middleware:    s.middleware,
			connectToSite: s.connectToSite,
			FieldLogger:   s.FieldLogger,
		}, nil
	}
	return nil, trace.BadParameter("unsupported database protocol %q",
		muxConn.Protocol())
}

// connectToSite connects to the database server running on a remote site
// over reverse tunnel and upgrades this end of the connection to TLS so
// the identity can be passed over it.
//
// The passed in context is expected to contain the identity information
// decoded from the client certificate by auth.Middleware.
func (s *ProxyServer) connectToSite(ctx context.Context) (net.Conn, error) {
	authContext, err := s.authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	tlsConfig, err := s.getConfigForServer(ctx, authContext.identity, authContext.server)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	siteConn, err := authContext.site.Dial(reversetunnel.DialParams{
		From:     &utils.NetAddr{AddrNetwork: "tcp", Addr: "@db-proxy"},
		To:       &utils.NetAddr{AddrNetwork: "tcp", Addr: reversetunnel.LocalNode},
		ServerID: fmt.Sprintf("%v.%v", authContext.server.GetName(), authContext.site.GetName()),
		ConnType: services.DatabaseTunnel,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	// Upgrade the connection so the client identity can be passed to the
	// remote server during TLS handshake. On the remote side, the connection
	// received from the reverse tunnel will be handled by tls.Server.
	siteConn = tls.Client(siteConn, tlsConfig)
	return siteConn, nil
}

// proxyContext contains parameters for a database session being proxied.
type proxyContext struct {
	// identity is the authorized client identity.
	identity tlsca.Identity
	// site is the remote site running the database server.
	site reversetunnel.RemoteSite
	// server is a server that has the requested database.
	server services.Server
	// db is a database the client is connecting to.
	db *services.Database
	// remote indicates if this is a request for remote cluster.
	remote bool
}

func (s *ProxyServer) authorize(ctx context.Context) (*proxyContext, error) {
	authContext, err := s.Authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	identity := authContext.Identity.GetIdentity()
	s.Debugf("Client identity: %#v.", identity)
	site, server, db, err := s.pickDatabaseServer(ctx, identity)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	s.Debugf("Will proxy to database %q on server %s.", db.Name, server)
	return &proxyContext{
		identity: identity,
		site:     site,
		server:   server,
		db:       db,
	}, nil
}

// pickDatabaseServer finds a database server instance to proxy requests
// to based on the routing information from the provided identity.
func (s *ProxyServer) pickDatabaseServer(ctx context.Context, identity tlsca.Identity) (reversetunnel.RemoteSite, services.Server, *services.Database, error) {
	site, err := s.Tunnel.GetSite(identity.RouteToDatabase.ClusterName)
	if err != nil {
		return nil, nil, nil, trace.Wrap(err)
	}
	accessPoint, err := site.CachingAccessPoint()
	if err != nil {
		return nil, nil, nil, trace.Wrap(err)
	}
	dbServers, err := accessPoint.GetDatabaseServers(ctx, defaults.Namespace)
	if err != nil {
		return nil, nil, nil, trace.Wrap(err)
	}
	s.Debugf("Available database servers on %v: %s.", site.GetName(), dbServers)
	// Find out which database servers proxy the database a user is
	// connecting to using routing information from identity.
	for _, server := range dbServers {
		for _, db := range server.GetDatabases() {
			if db.Name == identity.RouteToDatabase.DatabaseName {
				// TODO(r0mant): Return all matching servers and round-robin
				// between them.
				return site, server, db, nil
			}
		}
	}
	return nil, nil, nil, trace.NotFound("database %q not found among registered database servers on cluster %q",
		identity.RouteToDatabase.DatabaseName,
		identity.RouteToDatabase.ClusterName)
}

// getConfigForServer returns TLS config used for establishing connection
// to a remote database server over reverse tunnel.
func (s *ProxyServer) getConfigForServer(ctx context.Context, identity tlsca.Identity, server services.Server) (*tls.Config, error) {
	privateKeyBytes, _, err := native.GenerateKeyPair("")
	if err != nil {
		return nil, trace.Wrap(err)
	}
	subject, err := identity.Subject()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	csr, err := tlsca.GenerateCertificateRequestPEM(subject, privateKeyBytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	response, err := s.AuthClient.SignDatabaseCSR(ctx, &proto.DatabaseCSRRequest{
		CSR:         csr,
		ClusterName: identity.RouteToDatabase.ClusterName,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	cert, err := tls.X509KeyPair(response.Cert, privateKeyBytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	s.Debug("Generated database certificate.")
	pool := x509.NewCertPool()
	for _, caCert := range response.CACerts {
		ok := pool.AppendCertsFromPEM(caCert)
		if !ok {
			return nil, trace.BadParameter("failed to append CA certificate")
		}
	}
	return &tls.Config{
		ServerName:   server.GetHostname(),
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
	}, nil
}

func getConfigForClient(conf *tls.Config, ap auth.AccessPoint, log logrus.FieldLogger) func(*tls.ClientHelloInfo) (*tls.Config, error) {
	return func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		var clusterName string
		var err error
		if info.ServerName != "" {
			clusterName, err = auth.DecodeClusterName(info.ServerName)
			if err != nil && !trace.IsNotFound(err) {
				log.Debugf("Ignoring unsupported cluster name %q.", info.ServerName)
			}
		}
		pool, err := auth.ClientCertPool(ap, clusterName)
		if err != nil {
			log.WithError(err).Error("Failed to retrieve client CA pool.")
			return nil, nil // Fall back to the default config.
		}
		tlsCopy := conf.Clone()
		tlsCopy.ClientCAs = pool
		return tlsCopy, nil
	}
}
