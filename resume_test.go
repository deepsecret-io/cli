// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deepsecret-io/sdk"
)

func TestFindPendingUpload(t *testing.T) {
	pending := []sdk.PendingUpload{
		{RevisionID: "3f2a9c1e-0000-4000-8000-000000000001"},
		{RevisionID: "3f2a9c1e-0000-4000-8000-000000000002"},
		{RevisionID: "7b11d0aa-0000-4000-8000-000000000003"},
	}
	if p, err := findPendingUpload(pending, "7B11"); err != nil || p.RevisionID != pending[2].RevisionID {
		t.Fatalf("prefix: %v, %v", p, err)
	}
	if p, err := findPendingUpload(pending, pending[1].RevisionID); err != nil || p.RevisionID != pending[1].RevisionID {
		t.Fatalf("full id: %v, %v", p, err)
	}
	if _, err := findPendingUpload(pending, "3f2a9c1e"); err == nil || !strings.Contains(err.Error(), "matches 2") {
		t.Fatalf("ambiguous: %v", err)
	}
	if _, err := findPendingUpload(pending, "7b1"); err == nil {
		t.Fatal("a prefix under 4 characters matched")
	}
}

// DEEPSECRET_TMPDIR moves interrupted uploads with the other temporary
// files, into a folder named for the user since it may be shared;
// otherwise they live in the config folder.
func TestUploadsDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(sdk.TempDirEnv, "")
	if got := uploadsDir(); got != filepath.Join(home, ".deepsecret", "uploads") {
		t.Fatalf("default: %s", got)
	}
	t.Setenv(sdk.TempDirEnv, "/big/disk")
	if got := uploadsDir(); got != fmt.Sprintf("/big/disk/deepsecret-uploads-%d", os.Getuid()) {
		t.Fatalf("with %s: %s", sdk.TempDirEnv, got)
	}
}

// A refreshed session token replaces the stored one in place, keeping the
// email, private to the user, with no temporary file left behind.
func TestSaveRefreshedToken(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := saveToken("old", "alice@example.com", time.Now().Add(time.Hour).UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if err := saveRefreshedToken("new", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	tf, err := loadTokenFile()
	if err != nil || tf.Token != "new" || tf.Email != "alice@example.com" {
		t.Fatalf("token file: %+v, %v", tf, err)
	}
	if info, err := os.Stat(tokenPath()); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("token file mode: %v, %v", info.Mode(), err)
	}
	entries, _ := os.ReadDir(configDir())
	if len(entries) != 1 {
		t.Fatalf("config folder holds %d files, want only the token", len(entries))
	}
}

func TestAgo(t *testing.T) {
	now := time.Now()
	for d, want := range map[time.Duration]string{
		10 * time.Second: "just now",
		5 * time.Minute:  "5m ago",
		3 * time.Hour:    "3h ago",
		72 * time.Hour:   "3d ago",
	} {
		if got := ago(now.Add(-d)); got != want {
			t.Errorf("%s: %q, want %q", d, got, want)
		}
	}
}
