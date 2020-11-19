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

	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/client/pgservicefile"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
)

// onListDatabases handles "tsh db ls" command.
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
	profile, err := client.StatusCurrent("", cf.Proxy)
	if err != nil {
		utils.FatalError(err)
	}
	showDatabases(servers, profile.Databases, cf.Verbose)
}

// onDatabaseLogin handles "tsh db login" command.
func onDatabaseLogin(cf *CLIConf) {
	tc, err := makeClient(cf, false)
	if err != nil {
		utils.FatalError(err)
	}
	var servers []services.Server
	err = client.RetryWithRelogin(cf.Context, tc, func() error {
		servers, err = tc.ListDatabaseServersFor(cf.Context, tc.DatabaseName)
		return trace.Wrap(err)
	})
	if err != nil {
		utils.FatalError(err)
	}
	if len(servers) == 0 {
		utils.FatalError(trace.NotFound(
			"database %q not found, use 'tsh db ls' to see registered databases", tc.DatabaseName))
	}
	// Retrieve the current profile to see if it has any active role requests.
	profile, err := client.StatusCurrent("", cf.Proxy)
	if err != nil {
		utils.FatalError(err)
	}
	// Obtain certificate with the database name encoded in it.
	log.Debugf("Requesting TLS certificate for database %q on cluster %q.",
		tc.DatabaseName, tc.SiteName)
	err = client.RetryWithRelogin(cf.Context, tc, func() error {
		return tc.ReissueUserCerts(cf.Context, client.ReissueParams{
			RouteToCluster:  tc.SiteName,
			RouteToDatabase: tc.DatabaseName,
			AccessRequests:  profile.ActiveRequests.AccessRequests,
		})
	})
	if err != nil {
		utils.FatalError(err)
	}
	// Refresh the profile and save Postgres connection profile.
	// TODO(r0mant): This needs to become db-specific.
	profile, err = client.StatusCurrent("", cf.Proxy)
	if err != nil {
		utils.FatalError(err)
	}
	err = pgservicefile.Add(tc.DatabaseName, profile)
	if err != nil {
		utils.FatalError(err)
	}
}

// onDatabaseLogout handles "tsh db logout" command.
func onDatabaseLogout(cf *CLIConf) {
	tc, err := makeClient(cf, false)
	if err != nil {
		utils.FatalError(err)
	}
	profile, err := client.StatusCurrent("", cf.Proxy)
	if err != nil {
		utils.FatalError(err)
	}
	var logout []string
	// If database name wasn't given on the command line, log out of all.
	if tc.DatabaseName == "" {
		logout = profile.Databases
	} else {
		var found bool
		for _, db := range profile.Databases {
			if db == tc.DatabaseName {
				found = true
				break
			}
		}
		if !found {
			utils.FatalError(trace.BadParameter("Not logged in database %q",
				tc.DatabaseName))
		}
		logout = []string{tc.DatabaseName}
	}
	for _, db := range logout {
		// Remove database access certificate from ~/.tsh/keys for the
		// specified database.
		err = tc.LogoutDatabase(db)
		if err != nil {
			utils.FatalError(err)
		}
		// Remove corresponding section from pg_service file.
		// TODO(r0mant): This needs to become database specific.
		err = pgservicefile.Delete(db)
		if err != nil {
			utils.FatalError(err)
		}
	}
	fmt.Printf("Logged out of databases %q\n", logout)
}

// onDatabaseEnv handles "tsh db env" command.
func onDatabaseEnv(cf *CLIConf) {
	profile, err := client.StatusCurrent("", cf.Proxy)
	if err != nil {
		utils.FatalError(err)
	}
	if len(profile.Databases) == 0 {
		utils.FatalError(trace.BadParameter("Please login using 'tsh db login' first"))
	}
	database := cf.DatabaseName
	if database == "" {
		if len(profile.Databases) > 1 {
			utils.FatalError(trace.BadParameter("Multiple databases are available (%v), please select the one to print environment for via --db flag",
				strings.Join(profile.Databases, ", ")))
		}
		database = profile.Databases[0]
	}
	env, err := pgservicefile.Env(database)
	if err != nil {
		utils.FatalError(err)
	}
	for k, v := range env {
		fmt.Printf("export %v=%v\n", k, v)
	}
}
