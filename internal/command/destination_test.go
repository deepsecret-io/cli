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
	"github.com/deepsecret-io/cli/internal/testutil"
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

// The default ./<revision-id>/ must be a directory: a file by that name is
// refused before the download and again before the write, also with
// --overwrite, and is left as it was.
func TestDefaultDirMustBeADirectory(t *testing.T) {
	const rev = "04a0b4f6-4d7b-4d14-b212-f2c0b1f97a2f"
	archive := secrets.UpcomingDownload{RevisionID: rev, PayloadType: "files"}
	listed := secrets.UpcomingDownload{RevisionID: rev, PayloadType: "files", Files: []secrets.FileMeta{{Name: "notes.txt", Size: 5}}}

	t.Chdir(t.TempDir())
	if err := os.WriteFile(rev, []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	refused := func(what string, err error, nothing string) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s: a file at ./%s was accepted", what, rev)
		}
		summary, detail := errs.Describe(err)
		if !strings.Contains(summary, rev+" is not a directory") || !strings.Contains(detail, "Pass --dir to choose the output directory") ||
			!strings.Contains(detail, nothing) {
			t.Fatalf("%s: %q, %q", what, summary, detail)
		}
	}
	for _, overwrite := range []bool{false, true} {
		refused("an archive", checkFilesDestination("", archive, overwrite), "Nothing was downloaded")
		refused("listed files", checkFilesDestination("", listed, overwrite), "Nothing was downloaded")
	}
	_, created, err := prepareFilesDir("", rev)
	refused("before the write", err, "Nothing was written")
	if created {
		t.Fatal("a refused file is reported as created")
	}
	if got, err := os.ReadFile(rev); err != nil || string(got) != "mine" {
		t.Fatalf("the file at ./%s: %q, %v", rev, got, err)
	}
}

// Right before the write, the default ./<revision-id>/ is created when it
// is missing, private to this user (also on Windows, where a plain mkdir
// would take the access list of the directory above), and a directory
// already there is used as it is. A --dir is the caller's, and is left to
// the SDK.
func TestPrepareFilesDir(t *testing.T) {
	const rev = "04a0b4f6-4d7b-4d14-b212-f2c0b1f97a2f"
	t.Chdir(t.TempDir())

	dir, created, err := prepareFilesDir("", rev)
	if err != nil || dir != "./"+rev || !created {
		t.Fatalf("no ./%s yet: %q, created %v, %v", rev, dir, created, err)
	}
	if info, err := os.Lstat(dir); err != nil || !info.IsDir() {
		t.Fatalf("./%s was not created: %v", rev, err)
	}
	testutil.AssertPrivate(t, dir)

	if err := os.WriteFile(filepath.Join(rev, "notes.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir, created, err = prepareFilesDir("", rev)
	if err != nil || dir != "./"+rev || created {
		t.Fatalf("an existing ./%s: %q, created %v, %v", rev, dir, created, err)
	}
	if got, err := os.ReadFile(filepath.Join(rev, "notes.txt")); err != nil || string(got) != "hello" {
		t.Fatalf("a file in the existing ./%s: %q, %v", rev, got, err)
	}

	dir, created, err = prepareFilesDir("out", rev)
	if err != nil || dir != "out" || created {
		t.Fatalf("--dir out: %q, created %v, %v", dir, created, err)
	}
	if _, err := os.Lstat("out"); !os.IsNotExist(err) {
		t.Fatalf("--dir out was created here: %v", err)
	}

	if _, _, err := prepareFilesDir("", "../etc"); err == nil || !strings.Contains(err.Error(), "is not a UUID") {
		t.Fatalf("a revision ID that is a path: %v", err)
	}
}
