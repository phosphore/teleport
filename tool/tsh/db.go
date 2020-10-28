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

package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gravitational/teleport/lib/asciitable"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/client/pg"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
)

func onListDatabases(cf *CLIConf) {
	tc, err := makeClient(cf, false)
	if err != nil {
		utils.FatalError(err)
	}
	var servers []services.Server
	err = client.RetryWithRelogin(cf.Context, tc, func() error {
		servers, err = tc.ListDatabaseServers(cf.Context)
		return trace.Wrap(err)
	})
	if err != nil {
		utils.FatalError(err)
	}
	sort.Slice(servers, func(i, j int) bool {
		return servers[i].GetName() < servers[j].GetName()
	})
	// Retrieve profile to be able to show which databases user is logged into.
	profile, _, err := client.Status("", cf.Proxy)
	if err != nil {
		utils.FatalError(err)
	}
	showDatabases(servers, profile.Databases, cf.Verbose)
}

func showDatabases(servers []services.Server, activeDatabases []string, verbose bool) {
	// TODO(r0mant): Add verbose mode, add labels like Apps have.
	t := asciitable.MakeTable([]string{"Name", "Description", "Labels"})
	for _, server := range servers {
		for _, db := range server.GetDatabases() {
			name := db.Name
			if utils.SliceContainsStr(activeDatabases, db.Name) {
				name = fmt.Sprintf("> %v", name)
			}
			t.AddRow([]string{name, db.Description, services.LabelsAsString(db.StaticLabels, db.DynamicLabels)})
		}
	}
	fmt.Println(t.AsBuffer().String())
}

func onDatabaseLogin(cf *CLIConf) {
	profile, _, err := client.Status("", cf.Proxy)
	if err != nil {
		utils.FatalError(err)
	}
	if profile == nil {
		utils.FatalError(trace.BadParameter("please login using 'tsh login' first"))
	}
	tc, err := makeClient(cf, false)
	if err != nil {
		utils.FatalError(err)
	}
	var servers []services.Server
	err = client.RetryWithRelogin(cf.Context, tc, func() error {
		servers, err = tc.ListDatabaseServersFor(cf.Context, cf.DatabaseName)
		return trace.Wrap(err)
	})
	if err != nil {
		utils.FatalError(err)
	}
	if len(servers) == 0 {
		utils.FatalError(trace.NotFound(
			"database %q not found, use 'tsh db ls' to see registered databases", cf.DatabaseName))
	}
	// Obtain certificate with the database name encoded in it.
	log.Debugf("Requesting TLS certificate for database %q on cluster %q.", cf.DatabaseName, profile.Cluster)
	err = client.RetryWithRelogin(cf.Context, tc, func() error {
		// TODO(r0mant): Preserve active role requests?
		return tc.ReissueUserCerts(cf.Context, client.ReissueParams{
			RouteToCluster:  profile.Cluster,
			RouteToDatabase: cf.DatabaseName,
		})
	})
	if err != nil {
		utils.FatalError(err)
	}
	// Refresh the profile and save Postgres connection profile.
	// TODO(r0mant): This needs to become db-specific.
	profile, _, err = client.Status("", cf.Proxy)
	if err != nil {
		utils.FatalError(err)
	}
	addr, err := utils.ParseAddr(profile.ProxyURL.Host)
	if err != nil {
		utils.FatalError(err)
	}
	serviceFile, err := pg.LoadServiceFile("")
	if err != nil {
		utils.FatalError(err)
	}
	err = serviceFile.Add(pg.ConnectProfile{
		Name:        cf.DatabaseName,
		Host:        addr.Host(),
		Port:        addr.Port(defaults.HTTPListenPort),
		SSLMode:     "verify-full", // TODO(r0mant): Support insecure mode.
		SSLRootCert: profile.CACertPath(),
		SSLCert:     profile.DatabaseCertPath(cf.DatabaseName),
		SSLKey:      profile.KeyPath(),
	})
	if err != nil {
		utils.FatalError(err)
	}
	fmt.Printf(`
Connection information for %[1]q has been saved to ~/.pg_service.conf.
You can connect to the database using the following command:

  $ psql "service=%[1]v user=<user> dbname=<dbname>"

Or configure environment variables and use regular CLI flags:

  $ eval $(tsh db env)
  $ psql -U <user> <database>

`, cf.DatabaseName)
}

func onDatabaseLogout(cf *CLIConf) {
	if cf.DatabaseName == "" {
		return
	}
	profile, _, err := client.Status("", cf.Proxy)
	if err != nil {
		utils.FatalError(err)
	}
	if profile == nil {
		utils.FatalError(trace.BadParameter("not logged in"))
	}
	var found bool
	for _, db := range profile.Databases {
		if db == cf.DatabaseName {
			found = true
			break
		}
	}
	if !found {
		utils.FatalError(trace.BadParameter("not logged in database %q", cf.DatabaseName))
	}
	tc, err := makeClient(cf, false)
	if err != nil {
		utils.FatalError(err)
	}
	// Remove database access certificate from ~/.tsh/keys for the specified
	// database.
	err = tc.LogoutDatabase(cf.DatabaseName)
	if err != nil {
		utils.FatalError(err)
	}
	// Remove corresponding section from pg_service file.
	// TODO(r0mant): This needs to become database specific.
	serviceFile, err := pg.LoadServiceFile("")
	if err != nil {
		utils.FatalError(err)
	}
	err = serviceFile.Delete(cf.DatabaseName)
	if err != nil {
		utils.FatalError(err)
	}
	fmt.Printf("logged out of database %q\n", cf.DatabaseName)
}

func onDatabaseEnv(cf *CLIConf) {
	profile, _, err := client.Status("", cf.Proxy)
	if err != nil {
		utils.FatalError(err)
	}
	if profile == nil {
		utils.FatalError(trace.BadParameter("please login using 'tsh login' first"))
	}
	if len(profile.Databases) == 0 {
		utils.FatalError(trace.BadParameter("please login using 'tsh db login' first"))
	}
	database := cf.DatabaseName
	if database == "" {
		if len(profile.Databases) > 1 {
			utils.FatalError(trace.BadParameter("multiple databases are available (%v), please select the one to print environment for via --db flag",
				strings.Join(profile.Databases, ", ")))
		}
		database = profile.Databases[0]
	}
	serviceFile, err := pg.LoadServiceFile("")
	if err != nil {
		utils.FatalError(err)
	}
	env, err := serviceFile.AsEnv(database)
	if err != nil {
		utils.FatalError(err)
	}
	for k, v := range env {
		fmt.Printf("export %v=%v\n", k, v)
	}
}
