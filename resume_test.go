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

func TestFindPending(t *testing.T) {
	uploads := []sdk.PendingUpload{
		{RevisionID: "3f2a9c1e-0000-4000-8000-000000000001"},
		{RevisionID: "3f2a9c1e-0000-4000-8000-000000000002"},
		{RevisionID: "7b11d0aa-0000-4000-8000-000000000003"},
	}
	downloads := []sdk.PendingDownload{
		{RevisionID: "c0ffee00-0000-4000-8000-000000000004"},
		{RevisionID: "7b11d0ab-0000-4000-8000-000000000005"},
	}
	if p, d, err := findPending(uploads, downloads, "3F2A9C1E-0000-4000-8000-000000000002"); err != nil || d != nil || p.RevisionID != uploads[1].RevisionID {
		t.Fatalf("full upload id: %v, %v, %v", p, d, err)
	}
	if p, d, err := findPending(uploads, downloads, "c0ff"); err != nil || p != nil || d.RevisionID != downloads[0].RevisionID {
		t.Fatalf("download prefix: %v, %v, %v", p, d, err)
	}
	if _, _, err := findPending(uploads, downloads, "3f2a9c1e"); err == nil || !strings.Contains(err.Error(), "matches 2") {
		t.Fatalf("two uploads: %v", err)
	}
	if _, _, err := findPending(uploads, downloads, "7b11d0a"); err == nil || !strings.Contains(err.Error(), "matches 2") {
		t.Fatalf("an upload and a download: %v", err)
	}
	if _, _, err := findPending(uploads, downloads, "7b1"); err == nil {
		t.Fatal("a prefix under 4 characters matched")
	}
	if _, _, err := findPending(uploads, downloads, "dead"); err == nil {
		t.Fatal("an unknown ID matched")
	}
}

// DEEPSECRET_TMPDIR moves interrupted uploads and downloads with the other
// temporary files, into folders named for the user since it may be
// shared; otherwise they live in the config folder.
func TestTransferDirs(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(sdk.TempDirEnv, "")
	if got := uploadsDir(); got != filepath.Join(home, ".deepsecret", "uploads") {
		t.Fatalf("default: %s", got)
	}
	if got := downloadsDir(); got != filepath.Join(home, ".deepsecret", "downloads") {
		t.Fatalf("default: %s", got)
	}
	t.Setenv(sdk.TempDirEnv, "/big/disk")
	if got := uploadsDir(); got != fmt.Sprintf("/big/disk/deepsecret-uploads-%d", os.Getuid()) {
		t.Fatalf("with %s: %s", sdk.TempDirEnv, got)
	}
	if got := downloadsDir(); got != fmt.Sprintf("/big/disk/deepsecret-downloads-%d", os.Getuid()) {
		t.Fatalf("with %s: %s", sdk.TempDirEnv, got)
	}
}

// Asked to resume a download, the command says how to continue it, and
// puts the secret ID from the local record into that command only when it
// is a UUID.
func TestResumeExplainsADownload(t *testing.T) {
	d := &sdk.PendingDownload{RevisionID: "7b11d0ab-0000-4000-8000-000000000005", SecretID: "3f2a9c1e-0000-4000-8000-000000000009"}
	err := discardDownload(d, false)
	if err == nil {
		t.Fatal("no error for a download")
	}
	if summary, detail := describeError(err); !strings.HasPrefix(summary, "7b11d0ab is an interrupted download") ||
		!strings.Contains(detail, "secret decrypt 3f2a9c1e-0000-4000-8000-000000000009 --revision 7b11d0ab-0000-4000-8000-000000000005") {
		t.Fatalf("continue hint: %q, %q", summary, detail)
	}
	d.SecretID = "x; rm -rf ~"
	err = discardDownload(d, false)
	if summary, detail := describeError(err); err == nil || strings.Contains(summary+detail, "rm -rf") {
		t.Fatalf("a hostile secret ID reached the command: %q, %q", summary, detail)
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
