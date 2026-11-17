// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/deepsecret-io/cli/internal/config"
	"github.com/deepsecret-io/cli/internal/testutil"
	"github.com/deepsecret-io/deepsecret-go/keys"
	"github.com/deepsecret-io/deepsecret-go/keystore"
	"github.com/deepsecret-io/deepsecret-go/trust"
)

// The key pair check says which keys a password protects.
func TestDoctorNotesAPasswordKey(t *testing.T) {
	testutil.SetHome(t, t.TempDir())
	save := func(password string) string {
		t.Helper()
		kp, err := keys.Generate()
		if err != nil {
			t.Fatal(err)
		}
		fp, err := keys.Fingerprint(kp)
		if err != nil {
			t.Fatal(err)
		}
		if err := keystore.Save(config.KeysDir(), fp, kp, password); err != nil {
			t.Fatal(err)
		}
		return fp
	}
	locked, open := save("pw"), save("")
	seen := 0
	for _, r := range checkLocalKeys() {
		switch {
		case strings.HasPrefix(r.detail, keys.ShortFingerprint(locked)):
			seen++
			if !r.ok || !strings.Contains(r.detail, "(encrypted)") {
				t.Errorf("password key: %+v", r)
			}
		case strings.HasPrefix(r.detail, keys.ShortFingerprint(open)):
			seen++
			if !r.ok || strings.Contains(r.detail, "(encrypted)") {
				t.Errorf("open key: %+v", r)
			}
		}
	}
	if seen != 2 {
		t.Errorf("saw %d of the 2 keys", seen)
	}
}

// A key file this user cannot read is named by its short fingerprint, with
// how to give it back or remove it.
func TestDoctorUnreadableKeyFile(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs Unix permissions and a non-root user")
	}
	testutil.SetHome(t, t.TempDir())
	kp, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	fp, err := keys.Fingerprint(kp)
	if err != nil {
		t.Fatal(err)
	}
	if err := keystore.Save(config.KeysDir(), fp, kp, ""); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(config.KeysDir(), fp+".json")
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	results := checkLocalKeys()
	if len(results) != 1 {
		t.Fatalf("results %+v", results)
	}
	r := results[0]
	if r.ok || !strings.HasPrefix(r.detail, keys.ShortFingerprint(fp)+" ") || strings.Contains(r.detail, fp) ||
		!strings.Contains(r.detail, "not readable by you") || !strings.Contains(r.fix, "chown") || !strings.Contains(r.fix, path) {
		t.Fatalf("an unreadable key file: %+v", r)
	}
}

// A key pair on this device that one of the user's other accounts uses is
// theirs, not an unregistered key; the account checked is not "another".
func TestOwnAccountOf(t *testing.T) {
	const fp = "843a26813b3c356a0bc47d9f6dc5f14d49358d62b9f4f4a9c48b5689af24fad0"
	known := []trust.KnownKey{
		{Email: "bob@example.com", Fingerprint: strings.Repeat("b", 64), State: trust.Accepted},
		{Email: "me@example.com", Fingerprint: strings.Repeat("c", 64), State: trust.Own},
		{Email: "labs@example.com", Fingerprint: fp, State: trust.Own},
	}
	if got := ownAccountOf(known, fp, "Me@Example.com"); got != "labs@example.com" {
		t.Errorf("another account's key: %q", got)
	}
	if got := ownAccountOf(known, fp, "labs@example.com"); got != "" {
		t.Errorf("the account checked: %q", got)
	}
	if got := ownAccountOf(known, strings.Repeat("b", 64), "me@example.com"); got != "" {
		t.Errorf("someone else's key: %q", got)
	}
}

// A warning shows its fix but is not a failed check.
func TestPrintChecksWarnings(t *testing.T) {
	failed, warned := printChecks([]checkResult{
		{name: "A", ok: true, detail: "fine"},
		{name: "B", ok: true, warn: true, detail: "kept on this device only", fix: "secret identity sync"},
		{name: "C", detail: "broken", fix: "fix it"},
	})
	if failed != 1 || warned != 1 {
		t.Fatalf("failed %d, warned %d; want 1 and 1", failed, warned)
	}
}
