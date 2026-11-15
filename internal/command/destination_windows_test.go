// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build windows

package command

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/deepsecret-io/deepsecret-go/secrets"

	"github.com/deepsecret-io/cli/internal/errs"
	"github.com/deepsecret-io/cli/internal/testutil"
)

// A junction at the default ./<revision-id>/ is refused like a symlink,
// before the download and before the write, also with --overwrite: it
// needs no privilege to create, and the files would land where it points.
func TestDefaultDirRefusesAJunction(t *testing.T) {
	const rev = "04a0b4f6-4d7b-4d14-b212-f2c0b1f97a2f"
	archive := secrets.UpcomingDownload{RevisionID: rev, PayloadType: "files"}
	listed := secrets.UpcomingDownload{RevisionID: rev, PayloadType: "files", Files: []secrets.FileMeta{{Name: "notes.txt", Size: 5}}}

	target := t.TempDir()
	t.Chdir(t.TempDir())
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", rev, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
	refused := func(what string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s: a junction at ./%s was accepted", what, rev)
		}
		summary, detail := errs.Describe(err)
		if !strings.Contains(summary, rev+" is a link") || !strings.Contains(detail, "Pass --dir to choose the output directory") {
			t.Fatalf("%s: %q, %q", what, summary, detail)
		}
	}
	for _, overwrite := range []bool{false, true} {
		refused("an archive", checkFilesDestination("", archive, overwrite))
		refused("listed files", checkFilesDestination("", listed, overwrite))
	}
	_, created, err := prepareFilesDir("", rev)
	refused("before the write", err)
	if created {
		t.Fatal("a refused junction is reported as created")
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) > 0 {
		t.Fatalf("the junction's target holds %s", entries[0].Name())
	}
}

// A directory at the default ./<revision-id>/ that other accounts may open
// is refused before the download and before the write, also with
// --overwrite: the sender chooses the revision ID, so someone else on this
// computer could have made it, and could change what decrypt writes in it.
func TestDefaultDirMustBePrivate(t *testing.T) {
	const rev = "04a0b4f6-4d7b-4d14-b212-f2c0b1f97a2f"
	archive := secrets.UpcomingDownload{RevisionID: rev, PayloadType: "files"}
	listed := secrets.UpcomingDownload{RevisionID: rev, PayloadType: "files", Files: []secrets.FileMeta{{Name: "notes.txt", Size: 5}}}

	t.Chdir(t.TempDir())
	if err := os.Mkdir(rev, 0o700); err != nil {
		t.Fatal(err)
	}
	testutil.Expose(t, rev)
	refused := func(what string, err error, nothing string) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s: a ./%s others may open was accepted", what, rev)
		}
		summary, detail := errs.Describe(err)
		if !strings.Contains(summary, rev+" is open to other users") || !strings.Contains(detail, "may open it") ||
			!strings.Contains(detail, nothing) || !strings.Contains(detail, "Pass --dir to choose the output directory") {
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
		t.Fatal("a refused directory is reported as created")
	}
}
