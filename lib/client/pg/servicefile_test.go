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

package pg

import (
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestServiceFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), pgServiceFile)

	serviceFile, err := LoadServiceFile(path)
	require.NoError(t, err)

	profile := ConnectProfile{
		Name:        "test",
		Host:        "localhost",
		Port:        5342,
		SSLMode:     "on",
		SSLRootCert: "ca.pem",
		SSLCert:     "cert.pem",
		SSLKey:      "key.pem",
	}

	err = serviceFile.Add(profile)
	require.NoError(t, err)

	env, err := serviceFile.AsEnv(profile.Name)
	require.NoError(t, err)
	require.Equal(t, map[string]string{
		"PGHOST":        profile.Host,
		"PGPORT":        strconv.Itoa(profile.Port),
		"PGSSLMODE":     profile.SSLMode,
		"PGSSLROOTCERT": profile.SSLRootCert,
		"PGSSLCERT":     profile.SSLCert,
		"PGSSLKEY":      profile.SSLKey,
	}, env)

	err = serviceFile.Delete(profile.Name)
	require.NoError(t, err)

	env, err = serviceFile.AsEnv(profile.Name)
	require.Error(t, err)
}
