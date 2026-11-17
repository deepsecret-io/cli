// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deepsecret-io/deepsecret-go/keystore"

	"github.com/deepsecret-io/cli/internal/auth"
	"github.com/deepsecret-io/cli/internal/config"
	"github.com/deepsecret-io/cli/internal/identity"
	"github.com/deepsecret-io/cli/internal/testutil"
)

// generateSetup gives a test of identity generate a home of its own, no
// credential (every case runs with --local and makes no request), and a
// terminal that is there or not. It returns how many times the new key
// password was asked for; the answer is "correct horse".
func generateSetup(t *testing.T, terminal bool) *int {
	t.Helper()
	testutil.SetHome(t, t.TempDir())
	t.Setenv("DS_API_KEY", "")
	t.Setenv("DS_API_URL", "")
	savedKey, savedOrigin := auth.FlagKey, auth.FlagKeyOrigin
	savedTerminal, savedPassword := keyPasswordTerminal, newKeyPassword
	t.Cleanup(func() {
		auth.FlagKey, auth.FlagKeyOrigin = savedKey, savedOrigin
		keyPasswordTerminal, newKeyPassword = savedTerminal, savedPassword
	})
	auth.FlagKey, auth.FlagKeyOrigin = "", ""
	asked := 0
	keyPasswordTerminal = func() bool { return terminal }
	newKeyPassword = func(context.Context, string) (string, error) {
		asked++
		return "correct horse", nil
	}
	return &asked
}

// onlyKeyPair is the one key pair generate wrote.
func onlyKeyPair(t *testing.T) string {
	t.Helper()
	names, err := identity.List()
	if err != nil || len(names) != 1 {
		t.Fatalf("key pairs on this device: %v, %v", names, err)
	}
	testutil.AssertPrivate(t, filepath.Join(config.KeysDir(), names[0]+".json"))
	return names[0]
}

// On a terminal, with no choice of protection, generate asks for a new
// password and saves the key pair protected by it; --password does the
// same, as before.
func TestGenerateAsksForAPasswordByDefault(t *testing.T) {
	for _, args := range [][]string{{}, {"--password"}} {
		asked := generateSetup(t, true)
		var err error
		out := stderrOf(t, func() { err = runRoot(append([]string{"identity", "generate", "--local"}, args...)...) })
		if err != nil {
			t.Fatalf("generate %v: %v", args, err)
		}
		if *asked != 1 {
			t.Errorf("generate %v asked for the password %d times", args, *asked)
		}
		if p := identity.Protection(onlyKeyPair(t)); p != keystore.ProtectionPassword {
			t.Errorf("generate %v saved a key pair with protection %q", args, p)
		}
		if strings.Contains(out, "Warning:") {
			t.Errorf("generate %v warned: %q", args, out)
		}
	}
}

// An empty password is refused, and nothing is written.
func TestGenerateRefusesAnEmptyPassword(t *testing.T) {
	generateSetup(t, true)
	newKeyPassword = func(context.Context, string) (string, error) { return "", nil }
	err := runRoot("identity", "generate", "--local")
	if err == nil || !strings.Contains(err.Error()+errsDetail(err), "--no-password") {
		t.Fatalf("empty password: %v", err)
	}
	if names, _ := identity.List(); len(names) != 0 {
		t.Errorf("%d key pairs written", len(names))
	}
}

// Clear storage is an explicit choice: --no-password saves the private
// keys in clear without asking for anything, terminal or not, and warns
// what that means.
func TestGenerateNoPassword(t *testing.T) {
	for _, terminal := range []bool{true, false} {
		asked := generateSetup(t, terminal)
		var err error
		out := stderrOf(t, func() { err = runRoot("identity", "generate", "--local", "--no-password") })
		if err != nil {
			t.Fatalf("terminal %v: %v", terminal, err)
		}
		if *asked != 0 {
			t.Errorf("terminal %v: --no-password asked for a password", terminal)
		}
		if p := identity.Protection(onlyKeyPair(t)); p != keystore.ProtectionNone {
			t.Errorf("terminal %v: protection %q", terminal, p)
		}
		out = strings.Join(strings.Fields(testutil.AnsiEscape.ReplaceAllString(out, "")), " ")
		if !strings.Contains(out, "Warning:") || !strings.Contains(out, "anyone who can read the key file can open every secret sent to this identity") {
			t.Errorf("terminal %v: no warning in %q", terminal, out)
		}
	}
}

// With no terminal to type a password on and no choice of protection,
// generate fails, names the choices and writes nothing; so does
// --password, which needs the terminal as much.
func TestGenerateWithoutATerminal(t *testing.T) {
	for _, args := range [][]string{{}, {"--password"}} {
		asked := generateSetup(t, false)
		err := runRoot(append([]string{"identity", "generate", "--local"}, args...)...)
		if err == nil {
			t.Fatalf("generate %v with no terminal wrote a key pair", args)
		}
		text := err.Error() + errsDetail(err)
		for _, want := range []string{"terminal", "--no-password", "--security-key", "--kms-arn"} {
			if !strings.Contains(text, want) {
				t.Errorf("generate %v: refusal %q does not say %q", args, text, want)
			}
		}
		if *asked != 0 {
			t.Errorf("generate %v asked for a password with no terminal", args)
		}
		if names, _ := identity.List(); len(names) != 0 {
			t.Errorf("generate %v: %d key pairs written", args, len(names))
		}
	}
}

// --no-password is the choice of no protection, so it goes with no flag
// that protects the key pair; each is refused before anything is asked or
// written.
func TestGenerateNoPasswordConflicts(t *testing.T) {
	asked := generateSetup(t, true)
	isolateAWS(t)
	for _, args := range []string{
		"--no-password --password",
		"--no-password --security-key --single",
		"--no-password --kms-arn " + testKMSARN + " --single",
	} {
		err := runRoot(append([]string{"identity", "generate", "--local"}, strings.Fields(args)...)...)
		if err == nil || !strings.Contains(err.Error(), "--no-password") {
			t.Errorf("generate %s: %v", args, err)
		}
	}
	if names, _ := identity.List(); len(names) != 0 || *asked != 0 {
		t.Errorf("%d key pairs written, password asked %d times", len(names), *asked)
	}
}
