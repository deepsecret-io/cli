// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package pending

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deepsecret-io/deepsecret-go/secrets"
)

func TestFindPending(t *testing.T) {
	uploads := []secrets.PendingUpload{
		{RevisionID: "3f2a9c1e-0000-4000-8000-000000000001"},
		{RevisionID: "3f2a9c1e-0000-4000-8000-000000000002"},
		{RevisionID: "7b11d0aa-0000-4000-8000-000000000003"},
	}
	downloads := []secrets.PendingDownload{
		{RevisionID: "c0ffee00-0000-4000-8000-000000000004"},
		{RevisionID: "7b11d0ab-0000-4000-8000-000000000005"},
	}
	if p, d, err := Find(uploads, downloads, "3F2A9C1E-0000-4000-8000-000000000002"); err != nil || d != nil || p.RevisionID != uploads[1].RevisionID {
		t.Fatalf("full upload id: %v, %v, %v", p, d, err)
	}
	if p, d, err := Find(uploads, downloads, "c0ff"); err != nil || p != nil || d.RevisionID != downloads[0].RevisionID {
		t.Fatalf("download prefix: %v, %v, %v", p, d, err)
	}
	if _, _, err := Find(uploads, downloads, "3f2a9c1e"); err == nil || !strings.Contains(err.Error(), "matches 2") {
		t.Fatalf("two uploads: %v", err)
	}
	if _, _, err := Find(uploads, downloads, "7b11d0a"); err == nil || !strings.Contains(err.Error(), "matches 2") {
		t.Fatalf("an upload and a download: %v", err)
	}
	if _, _, err := Find(uploads, downloads, "7b1"); err == nil {
		t.Fatal("a prefix under 4 characters matched")
	}
	if _, _, err := Find(uploads, downloads, "dead"); err == nil {
		t.Fatal("an unknown ID matched")
	}
}

// DEEPSECRET_TMPDIR moves interrupted uploads and downloads with the other
// temporary files, into folders named for the user since it may be
// shared; otherwise they live in the config folder.
func TestTransferDirs(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(secrets.TempDirEnv, "")
	if got := UploadsDir(); got != filepath.Join(home, ".deepsecret", "uploads") {
		t.Fatalf("default: %s", got)
	}
	if got := DownloadsDir(); got != filepath.Join(home, ".deepsecret", "downloads") {
		t.Fatalf("default: %s", got)
	}
	t.Setenv(secrets.TempDirEnv, "/big/disk")
	if got := UploadsDir(); got != fmt.Sprintf("/big/disk/deepsecret-uploads-%d", os.Getuid()) {
		t.Fatalf("with %s: %s", secrets.TempDirEnv, got)
	}
	if got := DownloadsDir(); got != fmt.Sprintf("/big/disk/deepsecret-downloads-%d", os.Getuid()) {
		t.Fatalf("with %s: %s", secrets.TempDirEnv, got)
	}
}
