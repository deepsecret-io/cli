// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/deepsecret-io/cli/internal/auth"
	"github.com/deepsecret-io/cli/internal/config"
	"github.com/deepsecret-io/cli/internal/errs"
	"github.com/deepsecret-io/cli/internal/safefile"
	"github.com/deepsecret-io/cli/internal/testutil"
)

// keyFlags sets the --api-key-file and --api-key-stdin flags for the rest
// of t.
func keyFlags(t *testing.T, file string, stdin bool) {
	t.Helper()
	savedFile, savedStdin := apiKeyFile, apiKeyStdin
	t.Cleanup(func() { apiKeyFile, apiKeyStdin = savedFile, savedStdin })
	apiKeyFile, apiKeyStdin = file, stdin
}

// stdinFrom makes a file holding content the standard input for the rest
// of t.
func stdinFrom(t *testing.T, content string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stdin")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdin
	t.Cleanup(func() {
		os.Stdin = saved
		_ = f.Close()
	})
	os.Stdin = f
}

// --api-key-stdin takes the first line of stdin and nothing after it: what
// follows, such as the text to encrypt, is still there for the command,
// from its first byte.
func TestAPIKeyStdinLeavesTheRestOfStdin(t *testing.T) {
	payload := strings.Repeat("the text to encrypt\n", 1000)
	keyFlags(t, "", true)
	stdinFrom(t, "ds_test_key\r\n"+payload)
	key, err := resolveAPIKey()
	if err != nil || key != "ds_test_key" {
		t.Fatalf("key %q, %v", key, err)
	}
	rest, err := io.ReadAll(os.Stdin)
	if err != nil {
		t.Fatal(err)
	}
	if string(rest) != payload {
		t.Fatalf("%d bytes of the %d after the key are left on stdin", len(rest), len(payload))
	}
}

// A key on stdin needs no line end, and a line that is empty or longer
// than a key can be is refused.
func TestAPIKeyStdinLine(t *testing.T) {
	keyFlags(t, "", true)
	stdinFrom(t, "ds_test_key")
	if key, err := resolveAPIKey(); err != nil || key != "ds_test_key" {
		t.Errorf("a key without a line end: %q, %v", key, err)
	}
	stdinFrom(t, strings.Repeat("k", maxAPIKeyLen)+"\n")
	if key, err := resolveAPIKey(); err != nil || len(key) != maxAPIKeyLen {
		t.Errorf("the longest key: %d bytes, %v", len(key), err)
	}
	for content, want := range map[string]string{
		"":                                     "could not read the API key from stdin",
		"\nds_test_key\n":                      "read an empty key",
		strings.Repeat("k", maxAPIKeyLen+1):    "without a line end",
		strings.Repeat("k", 3*maxAPIKeyLen+17): "without a line end",
	} {
		stdinFrom(t, content)
		if _, err := resolveAPIKey(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%d bytes on stdin: %v, want %q", len(content), err, want)
		}
	}
}

// An --api-key-file other accounts may open is refused, as the token and
// config files are, with the command that fixes it. One private to the
// user is read.
func TestAPIKeyFileMustBePrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes do not say who may open a file on Windows")
	}
	path := filepath.Join(t.TempDir(), "key.txt")
	if err := os.WriteFile(path, []byte("ds_test_key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	keyFlags(t, path, false)
	if key, err := resolveAPIKey(); err != nil || key != "ds_test_key" {
		t.Fatalf("a private key file: %q, %v", key, err)
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o666} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		key, err := resolveAPIKey()
		if !errors.Is(err, safefile.ErrNotPrivate) {
			t.Fatalf("mode %o: %q, %v; want ErrNotPrivate", mode, key, err)
		}
		if summary, detail := errs.Describe(err); !strings.HasPrefix(summary, "--api-key-file: ") || !strings.Contains(detail, "chmod 600") {
			t.Errorf("mode %o: %q, %q", mode, summary, detail)
		}
	}
	// A file too long to be a key is refused for that, whatever its mode.
	if err := os.WriteFile(path, []byte(strings.Repeat("k", maxAPIKeyLen+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveAPIKey(); err == nil || !strings.Contains(err.Error(), "it should hold only the key") {
		t.Errorf("a long file: %v", err)
	}
	keyFlags(t, filepath.Join(t.TempDir(), "missing"), false)
	if _, err := resolveAPIKey(); err == nil || !strings.Contains(err.Error(), "could not read --api-key-file") {
		t.Errorf("a missing file: %v", err)
	}
}

// A ~/.deepsecret other accounts may open stops every command before it
// reads a key or the keys it trusts from there, with the command that
// fixes it.
func TestConfigDirMustBePrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes do not say who may open a folder on Windows")
	}
	testutil.SetHome(t, t.TempDir())
	t.Setenv("DS_API_KEY", "")
	savedKey, savedOrigin := auth.FlagKey, auth.FlagKeyOrigin
	t.Cleanup(func() { auth.FlagKey, auth.FlagKeyOrigin = savedKey, savedOrigin })
	auth.FlagKey, auth.FlagKeyOrigin = "", ""
	if err := os.Mkdir(config.Dir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(config.Dir(), 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(config.Dir(), 0o700) })
	err := runRoot("identity", "list")
	if !errors.Is(err, safefile.ErrNotPrivate) {
		t.Fatalf("%v, want ErrNotPrivate", err)
	}
	if _, detail := errs.Describe(err); !strings.Contains(detail, "chmod 700") {
		t.Errorf("detail %q", detail)
	}
	if err := runRoot("help"); err != nil {
		t.Errorf("help: %v", err)
	}
}

// Logout removes the token from this device whatever the server says, but
// fails when the server did not revoke it: the session is still valid, and
// a script must not take it for ended.
func TestLogoutFailsWhenTheServerDoesNotRevoke(t *testing.T) {
	testutil.SetHome(t, t.TempDir())
	saved := revokeToken
	t.Cleanup(func() { revokeToken = saved })
	logout := func() error {
		cmd := newLogoutCmd()
		cmd.SetArgs([]string{})
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		var err error
		testutil.StderrOf(t, func() { err = cmd.Execute() })
		return err
	}

	var sent string
	revokeToken = func(_ context.Context, _, token string) error {
		sent = token
		return errors.New("connection refused")
	}
	if err := config.SaveToken("session-token", "alice@example.com", "2099-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	err := logout()
	if err == nil || !strings.Contains(err.Error(), "could not revoke the login token") {
		t.Fatalf("a failed revoke: %v", err)
	}
	if _, detail := errs.Describe(err); !strings.Contains(detail, "removed from this device") || !strings.Contains(detail, "stays valid") {
		t.Errorf("detail %q", detail)
	}
	if sent != "session-token" {
		t.Errorf("revoked %q", sent)
	}
	if _, err := config.LoadTokenFile(); !os.IsNotExist(err) {
		t.Errorf("the token file after a failed revoke: %v, want it removed", err)
	}

	revokeToken = func(context.Context, string, string) error { return nil }
	if err := config.SaveToken("session-token", "alice@example.com", "2099-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if err := logout(); err != nil {
		t.Fatalf("a revoked session: %v", err)
	}
	if _, err := config.LoadTokenFile(); !os.IsNotExist(err) {
		t.Errorf("the token file after logout: %v, want it removed", err)
	}
}
