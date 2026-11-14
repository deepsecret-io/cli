// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package safefile

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/deepsecret-io/cli/internal/errs"
	"github.com/deepsecret-io/cli/internal/testutil"
)

// A decrypted file whose write fails is removed, not left half written.
func TestWriteAndCloseRemovesPartialFile(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "secret.txt")
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.Close() // the write below fails on the closed file
	if err := writeAndClose(f, dest, []byte("plaintext")); err == nil {
		t.Fatal("write to a closed file succeeded")
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Errorf("%s was left behind: %v", dest, err)
	}

	ok := filepath.Join(t.TempDir(), "ok.txt")
	if err := Write(ok, []byte("plaintext"), 0o600, false); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(ok); err != nil || string(data) != "plaintext" {
		t.Errorf("written: %q, %v", data, err)
	}
}

// With --overwrite, a decrypted file replaces the old one: it is private
// (0600, or an owner-only ACL on Windows), not left with the old file's
// access, and a link at -o is replaced, never written through.
func TestSafeWriteFileOverwriteReplaces(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(dest, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dest, 0o644); err != nil {
		t.Fatal(err)
	}
	err := Write(dest, []byte("new"), 0o600, false)
	if err == nil {
		t.Fatal("without --overwrite an existing file was replaced")
	}
	if summary, detail := errs.Describe(err); !strings.HasSuffix(summary, "secret.txt already exists") || !strings.Contains(detail, "--overwrite") {
		t.Fatalf("without --overwrite: %q, %q", summary, detail)
	}
	if err := Write(dest, []byte("new"), 0o600, true); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(dest); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("after overwrite: %v, %v; want a regular file", info, err)
	}
	testutil.AssertPrivate(t, dest)
	if data, _ := os.ReadFile(dest); string(data) != "new" {
		t.Fatalf("after overwrite the file holds %q", data)
	}

	elsewhere := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(elsewhere, []byte("untouched"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(dest); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, dest); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("creating a symlink needs a privilege this account lacks: %v", err)
		}
		t.Fatal(err)
	}
	if err := Write(dest, []byte("newer"), 0o600, false); err == nil {
		t.Fatal("without --overwrite a link at -o was written")
	}
	if err := Write(dest, []byte("newer"), 0o600, true); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(elsewhere); string(data) != "untouched" {
		t.Errorf("the decrypted data was written through the link: %q", data)
	}
	if info, err := os.Lstat(dest); err != nil || !info.Mode().IsRegular() {
		t.Errorf("after overwrite: %v, %v; want a regular file", info, err)
	}
	testutil.AssertPrivate(t, dest)
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("the output folder holds %d entries; a temporary file was left", len(entries))
	}
}

// MkdirExclusive makes a new folder private to this user (0700, or an
// owner-only ACL on Windows) and never uses what is at the path already:
// a folder or a file there is refused as existing, and left as it is. It
// makes no parents.
func TestMkdirExclusive(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "out")
	if err := MkdirExclusive(dir); err != nil {
		t.Fatal(err)
	}
	testutil.AssertPrivate(t, dir)

	if err := MkdirExclusive(dir); !errors.Is(err, os.ErrExist) {
		t.Errorf("a folder already there: %v, want os.ErrExist", err)
	}

	file := filepath.Join(parent, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := MkdirExclusive(file); !errors.Is(err, os.ErrExist) {
		t.Errorf("a file already there: %v, want os.ErrExist", err)
	}
	if data, err := os.ReadFile(file); err != nil || string(data) != "x" {
		t.Errorf("the file already there: %q, %v", data, err)
	}

	if err := MkdirExclusive(filepath.Join(parent, "missing", "out")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a missing parent: %v, want os.ErrNotExist", err)
	}
}
