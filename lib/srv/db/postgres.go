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
	"crypto/x509/pkix"
	"fmt"
	"io"
	"net"

	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/native"
	"github.com/gravitational/teleport/lib/auth/proto"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/rds/rdsutils"

	"github.com/jackc/pgconn"
	"github.com/jackc/pgproto3/v2"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/sirupsen/logrus"
)

// databaseProxy defines an interface a database proxy should implement.
type databaseProxy interface {
	// handleConnection takes the client connection, handles all database
	// specific startup actions and starts proxying to remote server.
	handleConnection(context.Context, net.Conn) error
}

// databaseEngine defines an interface for specific database protocol engine
// such as postgres or mysql.
type databaseEngine interface {
	// handleConnection takes the connection from the proxy and starts
	// proxying it to the particular database instance.
	handleConnection(context.Context, *sessionContext, net.Conn) error
}

type postgresProxy struct {
	tlsConfig     *tls.Config
	middleware    *auth.Middleware
	connectToSite func(context.Context) (net.Conn, error)
	logrus.FieldLogger
}

func (p *postgresProxy) handleConnection(ctx context.Context, clientConn net.Conn) (err error) {
	startupMessage, tlsConn, backend, err := p.handleStartup(ctx, clientConn)
	if err != nil {
		return trace.Wrap(err)
	}
	defer func() {
		if err != nil {
			if err := backend.Send(toErrorResponse(err)); err != nil {
				p.WithError(err).Error("Failed to send error to backend.")
			}
		}
	}()
	ctx, err = p.middleware.WrapContext(ctx, tlsConn)
	if err != nil {
		return trace.Wrap(err)
	}
	siteConn, err := p.connectToSite(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	defer siteConn.Close()
	err = p.proxyToSite(ctx, tlsConn, siteConn, startupMessage)
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// handleStartup handles the initial protocol exchange between the Postgres
// client (e.g. psql) and this proxy.
//
// Returns the startup message that contains initial connect parameters and
// the upgraded TLS connection.
func (p *postgresProxy) handleStartup(ctx context.Context, clientConn net.Conn) (*pgproto3.StartupMessage, *tls.Conn, *pgproto3.Backend, error) {
	// Backend acts as a server for the Postgres wire protocol.
	backend := pgproto3.NewBackend(pgproto3.NewChunkReader(clientConn), clientConn)
	startupMessage, err := backend.ReceiveStartupMessage()
	if err != nil {
		return nil, nil, nil, trace.Wrap(err)
	}
	p.Debugf("Received startup message: %#v.", startupMessage)
	// When initiating an encrypted connection, psql will first check with
	// the server whether it supports TLS by sending an SSLRequest message.
	//
	// Once the server has indicated the support (by sending 'S' in reply),
	// it will send a StartupMessage with the connection parameters such as
	// user name, database name, etc.
	//
	// https://www.postgresql.org/docs/13/protocol-flow.html#id-1.10.5.7.11
	switch m := startupMessage.(type) {
	case *pgproto3.SSLRequest:
		// Send 'S' back to indicate TLS support to the client.
		_, err := clientConn.Write([]byte("S"))
		if err != nil {
			return nil, nil, nil, trace.Wrap(err)
		}
		// Upgrade the connection to TLS and wait for the next message
		// which should be of the StartupMessage type.
		clientConn = tls.Server(clientConn, p.tlsConfig)
		return p.handleStartup(ctx, clientConn)
	case *pgproto3.StartupMessage:
		// TLS connection between the client and this proxy has been
		// established, just return the startup message.
		tlsConn, ok := clientConn.(*tls.Conn)
		if !ok {
			return nil, nil, nil, trace.BadParameter(
				"expected tls connection, got %T", clientConn)
		}
		return m, tlsConn, backend, nil
	}
	return nil, nil, nil, trace.BadParameter(
		"unsupported startup message: %#v", startupMessage)
}

// proxyToSite starts proxying all traffic received from Postgres client
// between this proxy and Teleport database service over reverse tunnel.
func (p *postgresProxy) proxyToSite(ctx context.Context, clientConn, siteConn net.Conn, startupMessage *pgproto3.StartupMessage) error {
	// Frontend acts as a client for the Posgres wire protocol.
	frontend := pgproto3.NewFrontend(pgproto3.NewChunkReader(siteConn), siteConn)
	// Pass the startup message along to the Teleport database server.
	err := frontend.Send(startupMessage)
	if err != nil {
		return trace.Wrap(err)
	}
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(siteConn, clientConn)
		errCh <- trace.Wrap(err, "failed proxying from client to site")
	}()
	go func() {
		_, err := io.Copy(clientConn, siteConn)
		errCh <- trace.Wrap(err, "failed proxying from site to client")
	}()
	var errs []error
	for i := 0; i < 2; i++ {
		select {
		case err := <-errCh:
			if err != nil && err != io.EOF {
				p.WithError(err).Warn("Connection problem.")
			}
		case <-ctx.Done():
			return trace.ConnectionProblem(nil, "context is closing")
		}
	}
	return trace.NewAggregate(errs...)
}

type postgresEngine struct {
	authClient     *auth.Client
	credentials    *credentials.Credentials
	rdsCACerts     map[string][]byte
	streamWriter   events.StreamWriter
	onSessionStart func(sessionContext) error
	onSessionEnd   func(sessionContext) error
	onQuery        func(sessionContext, string) error
	clock          clockwork.Clock
	logrus.FieldLogger
}

// toErrorResponse converts the provided error to a Postgres wire protocol
// error message response so the client such as psql can display it
// appropriately.
func toErrorResponse(err error) *pgproto3.ErrorResponse {
	// Wrapped error is not public in the pgconn package so use an
	// ephemeral interface to get access to the unwrap method.
	type pgError interface{ Unwrap() error }
	wrappedErr, ok := trace.Unwrap(err).(pgError)
	if !ok {
		return &pgproto3.ErrorResponse{Message: err.Error()}
	}
	pgErr, ok := wrappedErr.Unwrap().(*pgconn.PgError)
	if !ok {
		return &pgproto3.ErrorResponse{Message: err.Error()}
	}
	return &pgproto3.ErrorResponse{
		Severity: pgErr.Severity,
		Code:     pgErr.Code,
		Message:  pgErr.Message,
		Detail:   pgErr.Detail,
	}
}

func (e *postgresEngine) handleConnection(ctx context.Context, sessionCtx *sessionContext, clientConn net.Conn) (err error) {
	// TODO(r0mant): Set deadline on the connection for startup message?
	client := pgproto3.NewBackend(pgproto3.NewChunkReader(clientConn), clientConn)
	defer func() {
		if err != nil {
			if err := client.Send(toErrorResponse(err)); err != nil {
				e.WithError(err).Error("Failed to send error to client.")
			}
		}
	}()
	// The proxy is supposed to pass a startup message it received from
	// the psql client over to us, so wait for it and extract database
	// and username from it.
	err = e.handleStartup(client, sessionCtx)
	if err != nil {
		return trace.Wrap(err)
	}
	err = e.checkAccess(sessionCtx)
	if err != nil {
		return trace.Wrap(err)
	}
	server, hijackedConn, err := e.connect(ctx, sessionCtx)
	if err != nil {
		return trace.Wrap(err)
	}
	err = e.makeClientReady(client, hijackedConn)
	if err != nil {
		return trace.Wrap(err)
	}
	// At this point Postgres client should be ready to start sending
	// messages: this is where psql prompt appears on the other side.
	err = e.onSessionStart(*sessionCtx)
	if err != nil {
		return trace.Wrap(err)
	}
	defer func() {
		err := e.onSessionEnd(*sessionCtx)
		if err != nil {
			e.Error("Failed to emit audit event.")
		}
	}()
	serverConn, err := pgconn.Construct(hijackedConn)
	if err != nil {
		return trace.Wrap(err)
	}
	defer func() {
		err = serverConn.Close(ctx)
		if err != nil {
			e.Error("Failed to close connection.")
		}
	}()
	// Now launch the message exchange relaying all intercepted messages b/w
	// the client (psql or other Postgres client) and the server (database).
	clientErrCh := make(chan error, 1)
	serverErrCh := make(chan error, 1)
	go e.receiveFromClient(client, server, clientErrCh, sessionCtx)
	go e.receiveFromServer(server, client, serverConn, serverErrCh, sessionCtx)
	select {
	case err := <-clientErrCh:
		e.WithError(err).Debug("Client done.")
	case err := <-serverErrCh:
		e.WithError(err).Debug("Server done.")
	case <-ctx.Done():
		e.Debug("Context canceled.")
	}
	return nil
}

// handleStartup receives a startup message from the proxy and updates
// the session context with the connection parameters.
func (e *postgresEngine) handleStartup(client *pgproto3.Backend, sessionCtx *sessionContext) error {
	startupMessageI, err := client.ReceiveStartupMessage()
	if err != nil {
		return trace.Wrap(err)
	}
	e.Debugf("Received startup message: %#v.", startupMessageI)
	startupMessage, ok := startupMessageI.(*pgproto3.StartupMessage)
	if !ok {
		return trace.BadParameter("expected *pgproto3.StartupMessage, got %T", startupMessageI)
	}
	sessionCtx.dbName = startupMessage.Parameters["database"]
	sessionCtx.dbUser = startupMessage.Parameters["user"]
	return nil
}

func (e *postgresEngine) checkAccess(sessionCtx *sessionContext) error {
	return sessionCtx.checker.CheckAccessToDatabase(
		defaults.Namespace, sessionCtx.dbName, sessionCtx.dbUser, sessionCtx.db)
}

// connect establishes the connection to the database instance and returns
// the hijacked connection and the frontend, an interface used for message
// exchange with the database.
func (e *postgresEngine) connect(ctx context.Context, sessionCtx *sessionContext) (*pgproto3.Frontend, *pgconn.HijackedConn, error) {
	connectConfig, err := e.getConnectConfig(ctx, sessionCtx)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	// TODO(r0mant): Instead of using pgconn to connect, in future it might
	// make sense to reimplement the connect logic which will give us more
	// control over the initial startup and ability to relay authentication
	// messages b/w server and client e.g. to get client's password.
	conn, err := pgconn.ConnectConfig(ctx, connectConfig)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	// Hijacked connection exposes some internal connection data, such as
	// parameters we'll need to relay back to the client (e.g. database
	// server version).
	hijackedConn, err := conn.Hijack()
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	frontend := pgproto3.NewFrontend(pgproto3.NewChunkReader(hijackedConn.Conn), hijackedConn.Conn)
	return frontend, hijackedConn, nil
}

// makeClientReady indicates to the Postgres client (such as psql) that the
// server is ready to accept messages from it.
func (e *postgresEngine) makeClientReady(client *pgproto3.Backend, hijackedConn *pgconn.HijackedConn) error {
	// AuthenticationOk indicates that the authentication was successful.
	e.Debug("Sending AuthenticationOk.")
	if err := client.Send(&pgproto3.AuthenticationOk{}); err != nil {
		return trace.Wrap(err)
	}
	// BackendKeyData provides secret-key data that the frontend must save
	// if it wants to be able to issue cancel requests later.
	e.Debugf("Sending BackendKeyData: PID=%v.", hijackedConn.PID)
	if err := client.Send(&pgproto3.BackendKeyData{ProcessID: hijackedConn.PID, SecretKey: hijackedConn.SecretKey}); err != nil {
		return trace.Wrap(err)
	}
	// ParameterStatuses contains parameters reported by the server such as
	// server version, relay them back to the client.
	e.Debugf("Sending ParameterStatuses: %v.", hijackedConn.ParameterStatuses)
	for k, v := range hijackedConn.ParameterStatuses {
		if err := client.Send(&pgproto3.ParameterStatus{Name: k, Value: v}); err != nil {
			return trace.Wrap(err)
		}
	}
	// ReadyForQuery indicates that the start-up is completed and the
	// frontend can now issue commands.
	e.Debug("Sending ReadyForQuery")
	if err := client.Send(&pgproto3.ReadyForQuery{}); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// receiveFromClient receives messages from the provided backend (which
// in turn receives them from psql or other client) and relays them to
// the frontend connected to the database instance.
func (e *postgresEngine) receiveFromClient(client *pgproto3.Backend, server *pgproto3.Frontend, clientErrCh chan<- error, sessionCtx *sessionContext) {
	log := e.WithField("from", "client")
	defer log.Debug("Stop receiving from client.")
	for {
		message, err := client.Receive()
		if err != nil {
			log.WithError(err).Errorf("Failed to receive message from client.")
			clientErrCh <- err
			return
		}
		log.Debugf("Received client message: %#v.", message)
		switch msg := message.(type) {
		case *pgproto3.Query:
			err := e.onQuery(*sessionCtx, msg.String)
			if err != nil {
				log.WithError(err).Error("Failed to emit audit event.")
			}
		case *pgproto3.Terminate:
			clientErrCh <- nil
			return
		}
		err = server.Send(message)
		if err != nil {
			log.WithError(err).Error("Failed to send message to server.")
			clientErrCh <- err
			return
		}
	}
}

// receiveFromServer receives messages from the provided frontend (which
// is connected to the database instance) and relays them back to the psql
// or other client via the provided backend.
func (e *postgresEngine) receiveFromServer(server *pgproto3.Frontend, client *pgproto3.Backend, serverConn *pgconn.PgConn, serverErrCh chan<- error, sessionCtx *sessionContext) {
	log := e.WithField("from", "server")
	defer log.Debug("Stop receiving from server.")
	for {
		message, err := server.Receive()
		if err != nil {
			if serverConn.IsClosed() {
				log.Debug("Server connection closed.")
				serverErrCh <- nil
				return
			}
			log.WithError(err).Errorf("Failed to receive message from server.")
			serverErrCh <- err
			return
		}
		log.Debugf("Received server message: %#v.", message)
		switch message.(type) {
		case *pgproto3.ErrorResponse:
		case *pgproto3.DataRow:
		case *pgproto3.CommandComplete:
		}
		err = client.Send(message)
		if err != nil {
			log.WithError(err).Error("Failed to send message to client.")
			serverErrCh <- err
			return
		}
	}
}

// getConnectConfig returns config that can be used to connect to the
// database instance.
func (e *postgresEngine) getConnectConfig(ctx context.Context, sessionCtx *sessionContext) (*pgconn.Config, error) {
	// The driver requires the config to be built by parsing the connection
	// string so parse the basic template and then fill in the rest of
	// parameters such as TLS configuration.
	config, err := pgconn.ParseConfig(fmt.Sprintf("postgres://%s@%s/?database=%s",
		sessionCtx.dbUser, sessionCtx.db.URI, sessionCtx.dbName))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	// RDS/Aurora use IAM authentication so request an auth token and
	// use it as a password.
	if sessionCtx.db.IsAWS() {
		config.Password, err = e.getAuthToken(sessionCtx)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}
	// TLS config will use client certificate for an onprem database or
	// will contain RDS root certificate for RDS/Aurora.
	config.TLSConfig, err = e.getTLSConfig(ctx, sessionCtx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return config, nil
}

// getAuthToken returns authorization token that will be used as a password
// when connecting to RDS/Aurora databases.
func (e *postgresEngine) getAuthToken(sessionCtx *sessionContext) (string, error) {
	e.Debugf("Generating auth token for %s.", sessionCtx)
	return rdsutils.BuildAuthToken(
		sessionCtx.db.URI,
		sessionCtx.db.AWS.Region,
		sessionCtx.dbUser,
		e.credentials)
}

// getTLSConfig builds the client TLS configuration for the session.
//
// For RDS/Aurora, the config must contain RDS root certificate as a trusted
// authority. For onprem we generate a client certificate signed by the host
// CA used to authenticate.
func (e *postgresEngine) getTLSConfig(ctx context.Context, sessionCtx *sessionContext) (*tls.Config, error) {
	addr, err := utils.ParseAddr(sessionCtx.db.URI)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	tlsConfig := &tls.Config{
		ServerName: addr.Host(),
		RootCAs:    x509.NewCertPool(),
	}
	// Add CA certificate to the trusted pool if it's present, e.g. when
	// connecting to RDS/Aurora which require AWS CA.
	if len(sessionCtx.db.CACert) != 0 {
		if !tlsConfig.RootCAs.AppendCertsFromPEM(sessionCtx.db.CACert) {
			return nil, trace.BadParameter("failed to append CA certificate to the pool")
		}
	} else if sessionCtx.db.IsAWS() {
		if rdsCA, ok := e.rdsCACerts[sessionCtx.db.AWS.Region]; ok {
			if !tlsConfig.RootCAs.AppendCertsFromPEM(rdsCA) {
				return nil, trace.BadParameter("failed to append CA certificate to the pool")
			}
		} else {
			e.Warnf("No RDS CA certificate for %v.", sessionCtx.db)
		}
	}
	// RDS/Aurora auth is done via an auth token so don't generate a client
	// certificate and exit here.
	if sessionCtx.db.IsAWS() {
		return tlsConfig, nil
	}
	// Otherwise, when connecting to an onprem database, generate a client
	// certificate. The database instance should be configured with
	// Teleport's CA obtained with 'tctl auth sign --type=db'.
	cert, cas, err := e.getClientCert(ctx, sessionCtx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	tlsConfig.Certificates = []tls.Certificate{*cert}
	for _, ca := range cas {
		if !tlsConfig.RootCAs.AppendCertsFromPEM(ca) {
			return nil, trace.BadParameter("failed to append CA certificate to the pool")
		}
	}
	return tlsConfig, nil
}

// getClientCert signs an ephemeral client certificate used by this
// server to authenticate with the database instance.
func (e *postgresEngine) getClientCert(ctx context.Context, sessionCtx *sessionContext) (cert *tls.Certificate, cas [][]byte, err error) {
	privateBytes, _, err := native.GenerateKeyPair("")
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	// Postgres requires the database username to be encoded as a common
	// name in the client certificate.
	subject := pkix.Name{CommonName: sessionCtx.dbUser}
	csr, err := tlsca.GenerateCertificateRequestPEM(subject, privateBytes)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	e.Debugf("Generating client certificate for %s.", sessionCtx)
	resp, err := e.authClient.GenerateDatabaseCert(ctx, &proto.DatabaseCertRequest{
		CSR: csr,
		TTL: proto.Duration(sessionCtx.identity.Expires.Sub(e.clock.Now())),
	})
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	clientCert, err := tls.X509KeyPair(resp.Cert, privateBytes)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	return &clientCert, resp.CACerts, nil
}
