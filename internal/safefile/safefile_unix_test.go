// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build !windows

package safefile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deepsecret-io/cli/internal/errs"
)

// A config or token file someone else may open is refused, as it is on
// Windows, with the command that fixes it.
func TestReadPrivateRefusesAnExposedFileUnix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token.json")
	if err := Write(path, []byte(`{"token":"t"}`), 0o600, false); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadPrivate(path); err != nil || string(got) != `{"token":"t"}` {
		t.Fatalf("a private file: %q, %v", got, err)
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		_, err := ReadPrivate(path)
		if !errors.Is(err, ErrNotPrivate) {
			t.Fatalf("mode %o: %v, want ErrNotPrivate", mode, err)
		}
		summary, detail := errs.Describe(err)
		if !strings.HasSuffix(summary, "token.json is open to other users") || !strings.Contains(detail, "may open it") ||
			!strings.Contains(detail, `chmod 600 "`+path+`"`) {
			t.Errorf("mode %o: %q, %q", mode, summary, detail)
		}
	}
	if _, err := ReadPrivate(filepath.Join(t.TempDir(), "missing.json")); !os.IsNotExist(err) {
		t.Errorf("a missing file: %v, want not exist", err)
	}
}

// A link at the path is refused like anything else there, whether it
// points at a folder or at nothing: the folder is never made through it,
// or where it points.
func TestMkdirExclusiveRefusesALink(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(parent, "missing")
	toFolder, dangling := filepath.Join(parent, "to-folder"), filepath.Join(parent, "dangling")
	if err := os.Symlink(target, toFolder); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(missing, dangling); err != nil {
		t.Fatal(err)
	}

	for _, link := range []string{toFolder, dangling} {
		if err := MkdirExclusive(link); !errors.Is(err, os.ErrExist) {
			t.Errorf("%s: %v, want os.ErrExist", filepath.Base(link), err)
		}
		if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Errorf("%s is no longer a link: %v", filepath.Base(link), err)
		}
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Errorf("the folder was made where the dangling link points: %v", err)
	}
}
