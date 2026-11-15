// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build !windows

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

// linkedRevision is the revision the link tests decrypt: its sender chose
// the ID, so they can plant a link by that name where the recipient
// decrypts.
const linkedRevision = "04a0b4f6-4d7b-4d14-b212-f2c0b1f97a2f"

// plantLink moves to a new working directory holding a link named after
// linkedRevision that points at target.
func plantLink(t *testing.T, target string) {
	t.Helper()
	t.Chdir(t.TempDir())
	if err := os.Symlink(target, linkedRevision); err != nil {
		t.Fatal(err)
	}
}

// assertEmptyDir fails t unless dir is a directory holding nothing.
func assertEmptyDir(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) > 0 {
		t.Fatalf("%s holds %s", dir, entries[0].Name())
	}
}

// assertLinkRefused fails t unless err refuses the link at the default
// directory and says how to choose another one.
func assertLinkRefused(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("a link at the default directory was accepted")
	}
	summary, detail := errs.Describe(err)
	if !strings.Contains(summary, linkedRevision+" is a link") || !strings.Contains(detail, "Pass --dir to choose the output directory") {
		t.Fatalf("a link at the default directory: %q, %q", summary, detail)
	}
}

// Before a download, decrypt refuses a link at the default
// ./<revision-id>/: the files would land wherever it points. --overwrite
// does not allow it, and nothing is created where it points.
func TestCheckFilesDestinationRefusesALink(t *testing.T) {
	archive := secrets.UpcomingDownload{RevisionID: linkedRevision, PayloadType: "files"}
	listed := secrets.UpcomingDownload{RevisionID: linkedRevision, PayloadType: "files", Files: []secrets.FileMeta{{Name: ".ssh/authorized_keys2", Size: 5}}}

	target := t.TempDir()
	plantLink(t, target)
	for _, tc := range []struct {
		name      string
		download  secrets.UpcomingDownload
		overwrite bool
	}{
		{"listed files", listed, false},
		{"listed files, --overwrite", listed, true},
		{"an archive", archive, false},
		{"an archive, --overwrite", archive, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkFilesDestination("", tc.download, tc.overwrite)
			assertLinkRefused(t, err)
			if _, detail := errs.Describe(err); !strings.Contains(detail, "Nothing was downloaded") {
				t.Fatalf("the detail %q", detail)
			}
			assertEmptyDir(t, target)
		})
	}

	// The link is refused before anything is tried where it points: a
	// target that takes no files gives the same answer, not a failed write.
	t.Run("a target that cannot be written", func(t *testing.T) {
		readOnly := t.TempDir()
		if err := os.Chmod(readOnly, 0o500); err != nil {
			t.Fatal(err)
		}
		plantLink(t, readOnly)
		assertLinkRefused(t, checkFilesDestination("", listed, false))
	})

	t.Run("a link to nothing", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "missing")
		plantLink(t, missing)
		assertLinkRefused(t, checkFilesDestination("", listed, false))
		if _, err := os.Lstat(missing); !os.IsNotExist(err) {
			t.Fatalf("the link's target was created: %v", err)
		}
	})

	// A link the caller names with --dir is their own choice.
	t.Run("--dir", func(t *testing.T) {
		if err := checkFilesDestination(linkedRevision, listed, false); err != nil {
			t.Fatalf("the link as --dir: %v", err)
		}
	})
}

// Right before the write, the default ./<revision-id>/ is created new and
// private, so a link planted there since the check is refused, not written
// through.
func TestPrepareFilesDirRefusesALink(t *testing.T) {
	t.Chdir(t.TempDir())
	dir, created, err := prepareFilesDir("", linkedRevision)
	if err != nil {
		t.Fatalf("no ./%s yet: %v", linkedRevision, err)
	}
	if dir != "./"+linkedRevision || !created {
		t.Fatalf("no ./%s yet: %q, created %v", linkedRevision, dir, created)
	}
	testutil.AssertPrivate(t, dir)

	// The same path, now a link.
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	if err := os.Symlink(target, linkedRevision); err != nil {
		t.Fatal(err)
	}
	_, created, err = prepareFilesDir("", linkedRevision)
	assertLinkRefused(t, err)
	if created {
		t.Fatal("a refused link is reported as created")
	}
	assertEmptyDir(t, target)

	missing := filepath.Join(t.TempDir(), "missing")
	plantLink(t, missing)
	_, _, err = prepareFilesDir("", linkedRevision)
	assertLinkRefused(t, err)
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatalf("the link's target was created: %v", err)
	}
}

// A private directory that was there before keeps its mode: decrypt
// only sets the mode of the one it creates.
func TestPrepareFilesDirKeepsAnExistingMode(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.Mkdir(linkedRevision, 0o500); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(linkedRevision)
	if err != nil {
		t.Fatal(err)
	}
	if _, created, err := prepareFilesDir("", linkedRevision); err != nil || created {
		t.Fatalf("an existing ./%s: created %v, %v", linkedRevision, created, err)
	}
	after, err := os.Lstat(linkedRevision)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode() != before.Mode() {
		t.Fatalf("an existing ./%s went from mode %v to %v", linkedRevision, before.Mode(), after.Mode())
	}
}

// A directory at the default ./<revision-id>/ that other accounts may open
// is refused before the download and before the write, also with
// --overwrite, and left as it was: the sender chooses the revision ID, so
// someone else on this computer could have made it, and could change what
// decrypt writes in it.
func TestDefaultDirMustBePrivate(t *testing.T) {
	archive := secrets.UpcomingDownload{RevisionID: linkedRevision, PayloadType: "files"}
	listed := secrets.UpcomingDownload{RevisionID: linkedRevision, PayloadType: "files", Files: []secrets.FileMeta{{Name: "notes.txt", Size: 5}}}

	t.Chdir(t.TempDir())
	if err := os.Mkdir(linkedRevision, 0o700); err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(linkedRevision, "planted.txt")
	if err := os.WriteFile(planted, []byte("theirs"), 0o600); err != nil {
		t.Fatal(err)
	}
	refused := func(what string, err error, nothing string) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s: a ./%s others may open was accepted", what, linkedRevision)
		}
		summary, detail := errs.Describe(err)
		if !strings.Contains(summary, linkedRevision+" is open to other users") || !strings.Contains(detail, "may open it") ||
			!strings.Contains(detail, nothing) || !strings.Contains(detail, "Pass --dir to choose the output directory") {
			t.Fatalf("%s: %q, %q", what, summary, detail)
		}
	}
	for _, mode := range []os.FileMode{0o777, 0o755} {
		if err := os.Chmod(linkedRevision, mode); err != nil {
			t.Fatal(err)
		}
		for _, overwrite := range []bool{false, true} {
			refused("an archive", checkFilesDestination("", archive, overwrite), "Nothing was downloaded")
			refused("listed files", checkFilesDestination("", listed, overwrite), "Nothing was downloaded")
		}
		_, created, err := prepareFilesDir("", linkedRevision)
		refused("before the write", err, "Nothing was written")
		if created {
			t.Fatal("a refused directory is reported as created")
		}
		if info, err := os.Lstat(linkedRevision); err != nil || info.Mode().Perm() != mode {
			t.Fatalf("./%s changed: %v, %v", linkedRevision, info.Mode(), err)
		}
		if got, err := os.ReadFile(planted); err != nil || string(got) != "theirs" {
			t.Fatalf("the file in ./%s: %q, %v", linkedRevision, got, err)
		}
	}
}
