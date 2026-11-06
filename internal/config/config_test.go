// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/deepsecret-io/cli/internal/errs"
	"github.com/deepsecret-io/cli/internal/testutil"
)

// The config file holds the API key: saving it makes the file private even
// when an older one was not, and replaces a link instead of writing
// through it.
func TestSaveConfigIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes and links differ on Windows")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(Path(), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Save(&Config{APIKey: "ds_test_key"}); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(Path()); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("config mode: %v, %v; want 0600", info, err)
	}

	elsewhere := filepath.Join(home, "elsewhere.json")
	if err := os.WriteFile(elsewhere, []byte("untouched"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(Path()); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, Path()); err != nil {
		t.Fatal(err)
	}
	if err := Save(&Config{APIKey: "ds_test_key"}); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(elsewhere); err != nil || string(data) != "untouched" {
		t.Errorf("the link's target was written: %q, %v", data, err)
	}
	if info, err := os.Lstat(Path()); err != nil || !info.Mode().IsRegular() {
		t.Errorf("config is not a regular file: %v, %v", info, err)
	}
	if c, err := Load(); err != nil || c.APIKey != "ds_test_key" {
		t.Errorf("config: %+v, %v", c, err)
	}
	entries, _ := os.ReadDir(Dir())
	if len(entries) != 1 {
		t.Errorf("config folder holds %d files, want only the config", len(entries))
	}
}

// A renewed session token that cannot be saved is a warning: the server
// revoked the stored one, so the next command needs a new login.
func TestSaveRefreshedTokenWarns(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	// A file where the config folder goes: nothing can be saved in it.
	if err := os.WriteFile(filepath.Join(home, ".deepsecret"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var err error
	out := testutil.StderrOf(t, func() { err = SaveRefreshedToken("new", time.Now().Add(time.Hour)) })
	if err == nil || !strings.Contains(out, "Warning: Could not save the renewed login session") || !strings.Contains(out, "secret login") {
		t.Fatalf("%v, %q", err, out)
	}
}

// A refreshed session token replaces the stored one in place, keeping the
// email, private to the user, with no temporary file left behind.
func TestSaveRefreshedToken(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := SaveToken("old", "alice@example.com", time.Now().Add(time.Hour).UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if err := SaveRefreshedToken("new", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	tf, err := LoadTokenFile()
	if err != nil || tf.Token != "new" || tf.Email != "alice@example.com" {
		t.Fatalf("token file: %+v, %v", tf, err)
	}
	if info, err := os.Stat(tokenPath()); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("token file mode: %v, %v", info.Mode(), err)
	}
	entries, _ := os.ReadDir(Dir())
	if len(entries) != 1 {
		t.Fatalf("config folder holds %d files, want only the token", len(entries))
	}
}

// Without a home directory CheckHome says what to do, and Dir refuses to give
// a path relative to the current folder.
func TestCheckHome(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	if err := CheckHome(); err != nil {
		t.Fatalf("with a home directory: %v", err)
	}

	t.Setenv("HOME", "relative/home")
	t.Setenv("USERPROFILE", "relative/home")
	if err := CheckHome(); err == nil || !strings.Contains(err.Error()+errs.JoinDetail("", err), "not an absolute path") {
		t.Fatalf("a relative home directory: %v", err)
	}

	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	err := CheckHome()
	if err == nil {
		t.Fatal("no home directory gave no error")
	}
	if summary, detail := errs.Describe(err); summary != "Cannot find your home directory" || !strings.Contains(detail, "Set HOME") {
		t.Fatalf("%q, %q", summary, detail)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("Dir gave a path without a home directory")
		}
	}()
	Dir()
}
