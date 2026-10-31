// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Key fingerprints name files in the keys directory, and the server
// supplies some of them: one that is not hex is never used as a path.
func TestKeyFileRefusesPaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(keysDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	// An encrypted key file outside the keys directory, where a hostile
	// fingerprint could point.
	if err := os.WriteFile(filepath.Join(home, "planted.json"), []byte(`{"encrypted":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, fp := range []string{"../../planted", "../planted", "..", "", "0123456789abcdef/../../planted"} {
		if _, ok := keyFile(fp); ok {
			t.Errorf("keyFile(%q) accepted a path", fp)
		}
		if isKeyPairEncrypted(fp) {
			t.Errorf("isKeyPairEncrypted(%q) read a file outside the keys directory", fp)
		}
		if existsKeyPair(fp) {
			t.Errorf("existsKeyPair(%q) found a file outside the keys directory", fp)
		}
		if got := resolveKeystoreFingerprint(fp); got != fp {
			t.Errorf("resolveKeystoreFingerprint(%q) = %q", fp, got)
		}
		if _, err := loadKeyPair(fp); err == nil {
			t.Errorf("loadKeyPair(%q) loaded a key", fp)
		}
	}
	if path, ok := keyFile(strings.Repeat("AB", 32)); !ok || path != filepath.Join(keysDir(), strings.Repeat("ab", 32)+".json") {
		t.Errorf("keyFile of a full fingerprint: %q, %v", path, ok)
	}
}

// The config file holds the API key: saving it makes the file private even
// when an older one was not, and replaces a link instead of writing
// through it.
func TestSaveConfigIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes and links differ on Windows")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(configDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath(), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(&Config{APIKey: "ds_test_key"}); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(configPath()); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("config mode: %v, %v; want 0600", info, err)
	}

	elsewhere := filepath.Join(home, "elsewhere.json")
	if err := os.WriteFile(elsewhere, []byte("untouched"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(configPath()); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, configPath()); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(&Config{APIKey: "ds_test_key"}); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(elsewhere); err != nil || string(data) != "untouched" {
		t.Errorf("the link's target was written: %q, %v", data, err)
	}
	if info, err := os.Lstat(configPath()); err != nil || !info.Mode().IsRegular() {
		t.Errorf("config is not a regular file: %v, %v", info, err)
	}
	if c, err := loadConfig(); err != nil || c.APIKey != "ds_test_key" {
		t.Errorf("config: %+v, %v", c, err)
	}
	entries, _ := os.ReadDir(configDir())
	if len(entries) != 1 {
		t.Errorf("config folder holds %d files, want only the config", len(entries))
	}
}

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
	if err := safeWriteFile(ok, []byte("plaintext"), 0o600, false); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(ok); err != nil || string(data) != "plaintext" {
		t.Errorf("written: %q, %v", data, err)
	}
}

// Decrypted output that cannot be written to stdout fails the command
// instead of reporting success with part of the secret.
func TestWriteStdoutReportsFailure(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	w.Close()
	stdout := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = stdout }()
	for _, terminal := range []bool{false, true} {
		saved := stdoutIsTerminal
		stdoutIsTerminal = terminal
		err := writeStdout([]byte("secret"))
		stdoutIsTerminal = saved
		if err == nil {
			t.Errorf("terminal=%v: writing to a closed stdout succeeded", terminal)
		}
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
	err := safeWriteFile(dest, []byte("new"), 0o600, false)
	if err == nil {
		t.Fatal("without --overwrite an existing file was replaced")
	}
	if summary, detail := describeError(err); !strings.HasSuffix(summary, "secret.txt already exists") || !strings.Contains(detail, "--overwrite") {
		t.Fatalf("without --overwrite: %q, %q", summary, detail)
	}
	if err := safeWriteFile(dest, []byte("new"), 0o600, true); err != nil {
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
	if err := safeWriteFile(dest, []byte("newer"), 0o600, false); err == nil {
		t.Fatal("without --overwrite a link at -o was written")
	}
	if err := safeWriteFile(dest, []byte("newer"), 0o600, true); err != nil {
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
