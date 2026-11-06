// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/deepsecret-io/cli/internal/config"
	"github.com/deepsecret-io/cli/internal/errs"
)

// An expired login says so, rather than "not logged in"; a saved API key
// is used without a login.
func TestResolveAuth(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	savedKey := FlagKey
	t.Cleanup(func() { FlagKey = savedKey })
	FlagKey = ""
	if err := config.SaveToken("old", "you@example.com", time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	_, _, err := Resolve()
	if summary, detail := errs.Describe(err); summary != "Your login session expired" || !strings.Contains(detail, "secret login") {
		t.Fatalf("an expired session: %q, %q", summary, detail)
	}
	if err := config.RemoveToken(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Resolve(); err == nil || err.Error() != "not logged in" {
		t.Fatalf("no session: %v", err)
	}
	if err := config.Save(&config.Config{APIKey: "ds_test_key"}); err != nil {
		t.Fatal(err)
	}
	if key, source, err := Resolve(); err != nil || key != "ds_test_key" || source != "saved API key" {
		t.Fatalf("a saved key: %q, %q, %v", key, source, err)
	}
}
