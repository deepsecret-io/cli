// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package testutil

import "testing"

// SetHome makes dir the home directory for the rest of t: HOME on Unix and
// USERPROFILE on Windows, where os.UserHomeDir reads that instead, so a
// test never touches the real ~/.deepsecret.
func SetHome(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
}
