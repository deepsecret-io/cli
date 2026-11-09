// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build windows

package command

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deepsecret-io/cli/internal/auth"
	"github.com/deepsecret-io/cli/internal/config"
	"github.com/deepsecret-io/cli/internal/testutil"
)

// doctor reports a login token others may open as a failed check with its
// fix, not as "not logged in".
func TestDoctorReportsAnExposedToken(t *testing.T) {
	testutil.SetHome(t, t.TempDir())
	saved := auth.FlagKey
	t.Cleanup(func() { auth.FlagKey = saved })
	auth.FlagKey = ""
	if err := config.SaveToken("token", "you@example.com", time.Now().Add(time.Hour).UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	testutil.Expose(t, filepath.Join(config.Dir(), "token.json"))
	got := checkAuth(context.Background())
	if len(got) != 1 || got[0].ok || got[0].name != "Login" || !strings.Contains(got[0].detail, "open to other users") || got[0].fix != "secret login" {
		t.Fatalf("doctor's login checks: %+v", got)
	}
}
