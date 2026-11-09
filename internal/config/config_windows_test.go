// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build windows

package config

import (
	"errors"
	"testing"
	"time"

	"github.com/deepsecret-io/cli/internal/safefile"
	"github.com/deepsecret-io/cli/internal/testutil"
)

// The API key and the login token are not read from a file someone else
// may open: they are no longer private, and someone may have put them
// there.
func TestLoadRefusesExposedCredentials(t *testing.T) {
	testutil.SetHome(t, t.TempDir())
	if err := Save(&Config{APIKey: "ds_test_key"}); err != nil {
		t.Fatal(err)
	}
	if err := SaveToken("token", "alice@example.com", time.Now().Add(time.Hour).UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	testutil.AssertPrivate(t, Dir())
	if c, err := Load(); err != nil || c.APIKey != "ds_test_key" {
		t.Fatalf("a private config: %+v, %v", c, err)
	}
	if token, err := LoadToken(); err != nil || token != "token" {
		t.Fatalf("a private token: %q, %v", token, err)
	}

	testutil.Expose(t, Path())
	if _, err := Load(); !errors.Is(err, safefile.ErrNotPrivate) {
		t.Errorf("an exposed config: %v, want ErrNotPrivate", err)
	}
	testutil.Expose(t, tokenPath())
	if _, err := LoadToken(); !errors.Is(err, safefile.ErrNotPrivate) {
		t.Errorf("LoadToken of an exposed token: %v, want ErrNotPrivate", err)
	}
	if _, err := LoadTokenFile(); !errors.Is(err, safefile.ErrNotPrivate) {
		t.Errorf("LoadTokenFile of an exposed token: %v, want ErrNotPrivate", err)
	}
	// logout still reads it, to revoke and remove it.
	if tf, err := LoadTokenFileToRevoke(); err != nil || tf.Token != "token" {
		t.Errorf("LoadTokenFileToRevoke of an exposed token: %+v, %v", tf, err)
	}

	// Saving again replaces the exposed file with a private one.
	if err := Save(&Config{APIKey: "ds_test_key"}); err != nil {
		t.Fatal(err)
	}
	testutil.AssertPrivate(t, Path())
	if _, err := Load(); err != nil {
		t.Errorf("the config saved again: %v", err)
	}
}
