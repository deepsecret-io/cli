// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package safefile

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/deepsecret-io/cli/internal/errs"
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

// With --overwrite, a decrypted file replaces the old one: it gets its own
// mode (0600), not the old file's, and a link at -o is replaced, never
// written through.
func TestSafeWriteFileOverwriteReplaces(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes and links differ on Windows")
	}
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
	if info, err := os.Lstat(dest); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("after overwrite: %v, %v; want a 0600 file", info, err)
	}
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
	if info, err := os.Lstat(dest); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Errorf("after overwrite: %v, %v; want a 0600 file", info, err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("the output folder holds %d entries; a temporary file was left", len(entries))
	}
}
