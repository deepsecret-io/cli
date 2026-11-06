// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deepsecret-io/deepsecret-go/secrets"

	"github.com/deepsecret-io/cli/internal/errs"
)

// Before a download, decrypt refuses what it foresees it cannot write: a
// file the server lists that already exists, or, for an archive whose
// names the server does not keep, the default ./<revision-id>/ already
// holding an earlier decrypt of it. --overwrite allows both, and a --dir
// the caller chose may hold other files.
func TestCheckFilesDestination(t *testing.T) {
	const rev = "04a0b4f6-4d7b-4d14-b212-f2c0b1f97a2f"
	archive := secrets.UpcomingDownload{RevisionID: rev, PayloadType: "files"}
	listed := secrets.UpcomingDownload{RevisionID: rev, PayloadType: "files", Files: []secrets.FileMeta{{Name: "notes.txt", Size: 5}}}

	t.Chdir(t.TempDir())
	if err := checkFilesDestination("", archive, false); err != nil {
		t.Fatalf("no ./%s yet: %v", rev, err)
	}
	if err := os.Mkdir(rev, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := checkFilesDestination("", archive, false); err != nil {
		t.Fatalf("an empty ./%s: %v", rev, err)
	}
	if err := os.MkdirAll(filepath.Join(rev, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	err := checkFilesDestination("", archive, false)
	if err == nil {
		t.Fatalf("./%s holding an earlier decrypt was accepted", rev)
	}
	if summary, detail := errs.Describe(err); !strings.Contains(summary, "is not empty") ||
		!strings.Contains(detail, "earlier decrypt") || !strings.Contains(detail, "Nothing was downloaded") {
		t.Fatalf("./%s holding an earlier decrypt: %q, %q", rev, summary, detail)
	}
	if err := checkFilesDestination("", archive, true); err != nil {
		t.Fatalf("with --overwrite: %v", err)
	}
	if err := checkFilesDestination(rev, archive, false); err != nil {
		t.Fatalf("the same folder as --dir: %v", err)
	}

	if err := os.WriteFile(filepath.Join(rev, "notes.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = checkFilesDestination(rev, listed, false)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("a listed file that exists: %v", err)
	}
	if _, detail := errs.Describe(err); !strings.Contains(detail, "Nothing was downloaded") || !strings.Contains(detail, "--overwrite") {
		t.Fatalf("a listed file that exists: the detail %q", detail)
	}
	if err := checkFilesDestination(rev, listed, true); err != nil {
		t.Fatalf("a listed file that exists, with --overwrite: %v", err)
	}
}
