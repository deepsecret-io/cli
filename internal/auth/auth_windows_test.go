// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build windows

package auth

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/deepsecret-io/cli/internal/config"
	"github.com/deepsecret-io/cli/internal/safefile"
	"github.com/deepsecret-io/cli/internal/testutil"
)

// A login token someone else may open is reported, not skipped for the
// saved API key: the user must learn it is exposed. The same goes for the
// config file when there is no login.
func TestResolveRefusesExposedCredentials(t *testing.T) {
	testutil.SetHome(t, t.TempDir())
	savedKey := FlagKey
	t.Cleanup(func() { FlagKey = savedKey })
	FlagKey = ""
	if err := config.Save(&config.Config{APIKey: "ds_test_key"}); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveToken("token", "you@example.com", time.Now().Add(time.Hour).UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(config.Dir(), "token.json")
	testutil.Expose(t, token)
	if key, _, err := Resolve(); !errors.Is(err, safefile.ErrNotPrivate) {
		t.Fatalf("an exposed token: %q, %v; want ErrNotPrivate", key, err)
	}

	if err := config.RemoveToken(); err != nil {
		t.Fatal(err)
	}
	testutil.Expose(t, config.Path())
	if key, _, err := Resolve(); !errors.Is(err, safefile.ErrNotPrivate) {
		t.Fatalf("an exposed config: %q, %v; want ErrNotPrivate", key, err)
	}
}
