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

package pgservicefile

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"text/template"

	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"gopkg.in/ini.v1"
)

// Add updates Postgres connection service file at the default location with
// the connection information for the provided profile.
func Add(name, user, database string, profile *client.ProfileStatus) error {
	serviceFile, err := Load("")
	if err != nil {
		return trace.Wrap(err)
	}
	addr, err := utils.ParseAddr(profile.ProxyURL.Host)
	if err != nil {
		return trace.Wrap(err)
	}
	err = serviceFile.Add(ConnectProfile{
		Name:        name,
		Host:        addr.Host(),
		Port:        addr.Port(defaults.HTTPListenPort),
		User:        user,
		Database:    database,
		SSLMode:     SSLModeVerifyFull, // TODO(r0mant): Support insecure mode.
		SSLRootCert: profile.CACertPath(),
		SSLCert:     profile.DatabaseCertPath(name),
		SSLKey:      profile.KeyPath(),
	})
	if err != nil {
		return trace.Wrap(err)
	}
	return tshMessageTpl.Execute(os.Stdout, map[string]string{
		"service":  name,
		"user":     user,
		"database": database,
	})
}

// Env returns environment variables for the provided Postgres service from
// the default connection service file.
func Env(name string) (map[string]string, error) {
	serviceFile, err := Load("")
	if err != nil {
		return nil, trace.Wrap(err)
	}
	env, err := serviceFile.Env(name)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return env, nil
}

// Delete deletes specified connection profile from the default Postgres
// service file.
func Delete(name string) error {
	serviceFile, err := Load("")
	if err != nil {
		return trace.Wrap(err)
	}
	err = serviceFile.Delete(name)
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// serviceFile represents Postgres connection service file.
//
// https://www.postgresql.org/docs/13/libpq-pgservice.html
type serviceFile struct {
	// iniFile is the underlying ini file.
	iniFile *ini.File
	// path is the service file path.
	path string
}

// Load loads Postgres connection service file from the provided path or the
// default location if it's not provided.
func Load(path string) (*serviceFile, error) {
	// If the file path wasn't provided, use the default location which
	// is .pg_service.conf file in the user's home directory.
	if path == "" {
		// TODO(r0mant): Check PGSERVICEFILE and PGSYSCONFDIR env vars as well.
		user, err := user.Current()
		if err != nil {
			return nil, trace.ConvertSystemError(err)
		}
		path = filepath.Join(user.HomeDir, pgServiceFile)
	}
	// Loose load will ignore file not found error.
	iniFile, err := ini.LooseLoad(path)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &serviceFile{
		iniFile: iniFile,
		path:    path,
	}, nil
}

// Add adds the provided connection profile to the service file and saves it.
//
// The profile goes into a separate section with the name equal to the
// name of the database that user is logged into and looks like this:
//
//   [postgres]
//   host=proxy.example.com
//   port=3080
//   sslmode=verify-full
//   sslrootcert=/home/user/.tsh/keys/proxy.example.com/certs.pem
//   sslcert=/home/user/.tsh/keys/proxy.example.com/alice-db/root/aurora-x509.pem
//   sslkey=/home/user/.tsh/keys/proxy.example.com/user
//
// With the profile like this, a user can refer to it using "service" psql
// parameter:
//
//   $ psql "service=postgres <other parameters>"
func (s *serviceFile) Add(profile ConnectProfile) error {
	section := s.iniFile.Section(profile.Name)
	if section != nil {
		s.iniFile.DeleteSection(profile.Name)
	}
	section, err := s.iniFile.NewSection(profile.Name)
	if err != nil {
		return trace.Wrap(err)
	}
	section.NewKey("host", profile.Host)
	section.NewKey("port", strconv.Itoa(profile.Port))
	if profile.User != "" {
		section.NewKey("user", profile.User)
	}
	if profile.Database != "" {
		section.NewKey("dbname", profile.Database)
	}
	section.NewKey("sslmode", profile.SSLMode)
	section.NewKey("sslrootcert", profile.SSLRootCert)
	section.NewKey("sslcert", profile.SSLCert)
	section.NewKey("sslkey", profile.SSLKey)
	ini.PrettyFormat = false // Pretty format breaks psql.
	return s.iniFile.SaveTo(s.path)
}

// Env returns the specified connection profile information as a set of
// environment variables recognized by Postgres clients.
func (s *serviceFile) Env(name string) (map[string]string, error) {
	section, err := s.iniFile.GetSection(name)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	host, err := section.GetKey("host")
	if err != nil {
		return nil, trace.Wrap(err)
	}
	port, err := section.GetKey("port")
	if err != nil {
		return nil, trace.Wrap(err)
	}
	sslMode, err := section.GetKey("sslmode")
	if err != nil {
		return nil, trace.Wrap(err)
	}
	sslRootCert, err := section.GetKey("sslrootcert")
	if err != nil {
		return nil, trace.Wrap(err)
	}
	sslCert, err := section.GetKey("sslcert")
	if err != nil {
		return nil, trace.Wrap(err)
	}
	sslKey, err := section.GetKey("sslkey")
	if err != nil {
		return nil, trace.Wrap(err)
	}
	env := map[string]string{
		"PGHOST":        host.Value(),
		"PGPORT":        port.Value(),
		"PGSSLMODE":     sslMode.Value(),
		"PGSSLROOTCERT": sslRootCert.Value(),
		"PGSSLCERT":     sslCert.Value(),
		"PGSSLKEY":      sslKey.Value(),
	}
	if section.HasKey("user") {
		user, err := section.GetKey("user")
		if err != nil {
			return nil, trace.Wrap(err)
		}
		env["PGUSER"] = user.Value()
	}
	if section.HasKey("dbname") {
		database, err := section.GetKey("dbname")
		if err != nil {
			return nil, trace.Wrap(err)
		}
		env["PGDATABASE"] = database.Value()
	}
	return env, nil
}

// Delete deletes the specified connection profile and saves the service file.
func (s *serviceFile) Delete(name string) error {
	s.iniFile.DeleteSection(name)
	return s.iniFile.SaveTo(s.path)
}

// ConnectProfile represents a single connection profile in the service file.
type ConnectProfile struct {
	// Name is the profile name.
	Name string
	// Host is the host to connect to.
	Host string
	// Port is the port number to connect to.
	Port int
	// User is an optional database user name.
	User string
	// Database is an optional database name.
	Database string
	// SSLMode is the SSL connection mode.
	SSLMode string
	// SSLRootCert is the CA certificate path.
	SSLRootCert string
	// SSLCert is the client certificate path.
	SSLCert string
	// SSLKey is the client key path.
	SSLKey string
}

// pgServiceFile is the default name of the Postgres service file.
const pgServiceFile = ".pg_service.conf"

// SSLModeVerifyFull is the Postgres SSL "verify-full" mode.
const SSLModeVerifyFull = "verify-full"

// tshMessage is printed after Postgres service file has been updated.
var tshMessageTpl = template.Must(template.New("").Parse(`
Connection information for PostgreSQL database "{{.service}}" has been saved.

You can now connect to the database using the following command:

  $ psql "service={{.service}}{{if not .user}} user=<user>{{end}}{{if not .database}} dbname=<dbname>{{end}}"

Or configure environment variables and use regular CLI flags:

  $ eval $(tsh db env)
  $ psql{{if not .user}} -U <user>{{end}}{{if not .database}} <dbname>{{end}}

`))
