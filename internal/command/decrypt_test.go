// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"strings"
	"testing"

	"github.com/deepsecret-io/deepsecret-go/keys"
	"github.com/deepsecret-io/deepsecret-go/secrets"

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
