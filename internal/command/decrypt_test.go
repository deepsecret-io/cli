// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deepsecret-io/deepsecret-go/keys"
	"github.com/deepsecret-io/deepsecret-go/secrets"

	"github.com/deepsecret-io/cli/internal/auth"
	"github.com/deepsecret-io/cli/internal/errs"
	"github.com/deepsecret-io/cli/internal/testutil"
)

// The Sender line says a key pair on this device signed the secret, never
// that it is the sender's registered key, whoever the server names.
func TestSenderLine(t *testing.T) {
	testutil.SetHome(t, t.TempDir())
	short := keys.ShortFingerprint(fullFP)
	for _, tc := range []struct {
		name   string
		result secrets.DecryptResult
		want   string
		absent string
	}{
		{"someone else", secrets.DecryptResult{SenderEmail: "bob@example.com", SenderFingerprint: fullFP}, "(their registered key)", "on this device"},
		{"one of your accounts", secrets.DecryptResult{SenderEmail: "me@example.com", SenderFingerprint: fullFP, SenderOwnKey: true, SenderOwnAccount: true}, "(a key on this device)", "registered key"},
		{"not recorded as yours", secrets.DecryptResult{SenderEmail: "bob@example.com", SenderFingerprint: fullFP, SenderOwnKey: true}, "(a key on this device)", "registered key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line := senderLine(&tc.result)
			if !strings.Contains(line, tc.result.SenderEmail) || !strings.Contains(line, short) || !strings.Contains(line, tc.want) {
				t.Errorf("%q, want %s, %s and %q", line, tc.result.SenderEmail, short, tc.want)
			}
			if strings.Contains(line, tc.absent) {
				t.Errorf("%q holds %q", line, tc.absent)
			}
		})
	}
}

// A secret signed with a key pair on this device, from a sender not
// recorded here as one of your accounts, opens with a warning saying so
// and what to do. Nothing is said for one of your accounts or for someone
// else's key.
func TestOwnKeyNotice(t *testing.T) {
	out := testutil.StderrOf(t, func() {
		printOwnKeyNotice(&secrets.DecryptResult{SenderEmail: "bob@example.com", SenderFingerprint: fullFP, SenderOwnKey: true})
	})
	for _, want := range []string{
		"Warning:",
		"This secret is signed with a key on this device",
		"It names bob@example.com as its sender, but this device has not recorded bob@example.com as one of your accounts.",
		"If bob@example.com is your account, sign in as it (secret login) and record it as yours on this device with:",
		"secret identity sync -i " + fullFP,
		"If that key is not registered for it yet, this also registers it and makes it your primary key.",
		"If it is not, you signed this secret and it was relabelled as from bob@example.com.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("%q does not hold %q", out, want)
		}
	}

	for name, r := range map[string]secrets.DecryptResult{
		"one of your accounts": {SenderEmail: "me@example.com", SenderFingerprint: fullFP, SenderOwnKey: true, SenderOwnAccount: true},
		"someone else's key":   {SenderEmail: "bob@example.com", SenderFingerprint: fullFP},
	} {
		if out := testutil.StderrOf(t, func() { printOwnKeyNotice(&r) }); out != "" {
			t.Errorf("%s: %q, want nothing", name, out)
		}
	}
}

// An -o file that exists is refused before anything is downloaded, unless
// --overwrite is given; a link there counts, as the write does not follow
// one.
func TestOutputFileIsCheckedBeforeTheDownload(t *testing.T) {
	testutil.SetHome(t, t.TempDir())
	t.Setenv("DS_API_KEY", "")
	savedKey, savedOrigin := auth.FlagKey, auth.FlagKeyOrigin
	t.Cleanup(func() { auth.FlagKey, auth.FlagKeyOrigin = savedKey, savedOrigin })
	auth.FlagKey, auth.FlagKeyOrigin = "", ""

	dir := t.TempDir()
	existing := filepath.Join(dir, "out.txt")
	if err := os.WriteFile(existing, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(filepath.Join(dir, "nowhere"), link); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	for _, path := range []string{existing, link} {
		err := checkOutputFree(path, false)
		if err == nil || !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("%s: %v", filepath.Base(path), err)
		}
		if _, detail := errs.Describe(err); !strings.Contains(detail, "--overwrite") {
			t.Errorf("detail %q", detail)
		}
		if err := checkOutputFree(path, true); err != nil {
			t.Errorf("%s with --overwrite: %v", filepath.Base(path), err)
		}
	}
	if err := checkOutputFree(filepath.Join(dir, "new.txt"), false); err != nil {
		t.Errorf("a new file: %v", err)
	}

	// The command stops there: with no credential it would otherwise fail
	// for that, before any request.
	err := runRoot("decrypt", testID, "-o", existing)
	if err == nil || !strings.Contains(err.Error(), existing+" already exists") {
		t.Fatalf("decrypt -o an existing file: %v", err)
	}
	if got, _ := os.ReadFile(existing); string(got) != "keep" {
		t.Errorf("the existing file now holds %q", got)
	}
}
