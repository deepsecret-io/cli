// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"io"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/deepsecret-io/sdk"
)

// runCmd executes cmd with args and returns its error. Every case here
// fails validation before any network call.
func runCmd(cmd *cobra.Command, args ...string) error {
	cmd.SetArgs(args)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	return cmd.Execute()
}

func TestRecipientsSummary(t *testing.T) {
	rs := []sdk.SecretRecipient{{Email: "alice@example.com"}, {Email: "bob@example.com"}, {Email: "carol@example.com"}}
	cases := map[string]struct {
		in   []sdk.SecretRecipient
		want string
	}{
		"none":  {nil, "-"},
		"one":   {rs[:1], "alice@example.com"},
		"three": {rs, "alice@example.com +2"},
	}
	for name, c := range cases {
		if got := recipientsSummary(c.in); got != c.want {
			t.Errorf("%s: got %q, want %q", name, got, c.want)
		}
	}
}

// whoami shows the free trial, not just "inactive", when there is no
// subscription.
func TestSubscriptionStatus(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	future, past := "2026-11-02T12:00:00Z", "2026-10-20T12:00:00Z"
	if got := subscriptionStatus("inactive", &future, now); !strings.HasPrefix(got, "Free trial, ends ") {
		t.Errorf("in trial: %q", got)
	}
	if got := subscriptionStatus("inactive", &past, now); !strings.HasPrefix(got, "inactive, free trial ended ") {
		t.Errorf("after trial: %q", got)
	}
	if got := subscriptionStatus("active", &future, now); got != "active" {
		t.Errorf("subscribed: %q", got)
	}
	if got := subscriptionStatus("inactive", nil, now); got != "inactive" {
		t.Errorf("no trial: %q", got)
	}
}

func TestLocalFileName(t *testing.T) {
	cases := []struct {
		name     string
		inputs   []string
		fallback string
		want     string
	}{
		{"", []string{"configs/db.env"}, "db.env", "db.env.cbor"},
		{"", []string{"a.txt", "b.txt"}, "a.txt (2 files)", "a.txt.cbor"},
		{"release", []string{"a.txt"}, "release", "release.cbor"},
		{"", nil, "message-20261026-120000", "message-20261026-120000.cbor"},
		{"../../etc/passwd", nil, "", "passwd.cbor"},
	}
	for _, c := range cases {
		if got := localFileName(c.name, c.inputs, c.fallback); got != c.want {
			t.Errorf("localFileName(%q, %v): got %q, want %q", c.name, c.inputs, got, c.want)
		}
	}
}

// A fingerprint is read aloud in two lines of eight groups of four, the
// same in identity show and identity verify, so both sides compare one
// layout.
func TestGroupFingerprint(t *testing.T) {
	got := groupFingerprint(fullFP)
	want := []string{"0123 4567 89ab cdef 0123 4567 89ab cdef", "0123 4567 89ab cdef 0123 4567 89ab cdef"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// What this device knows of the key the server lists for someone.
func TestKnownKeyStatus(t *testing.T) {
	seen := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	other := strings.Repeat("f", 64)
	if got := knownKeyStatus(fullFP, nil); !strings.HasPrefix(got, "not known yet") {
		t.Errorf("unknown: %q", got)
	}
	if got := knownKeyStatus(fullFP, []sdk.KnownKey{{Fingerprint: fullFP, State: sdk.KeyVerified, FirstSeen: seen}}); !strings.HasPrefix(got, "verified, since ") {
		t.Errorf("known: %q", got)
	}
	if got := knownKeyStatus(fullFP, []sdk.KnownKey{{Fingerprint: other, State: sdk.KeyFirstUse, FirstSeen: seen}}); !strings.Contains(got, "changed") || !strings.HasSuffix(got, " from "+other[:16]) {
		t.Errorf("changed: %q", got)
	}
	replaced := []sdk.KnownKey{
		{Fingerprint: fullFP, State: sdk.KeyVerified, FirstSeen: seen, Replaced: true},
		{Fingerprint: other, State: sdk.KeyAccepted, FirstSeen: seen},
	}
	if got := knownKeyStatus(fullFP, replaced); !strings.Contains(got, "replaced") || !strings.HasSuffix(got, " by "+other[:16]) {
		t.Errorf("replaced: %q", got)
	}
	if got := knownKeyStatus(fullFP, []sdk.KnownKey{{Fingerprint: fullFP, State: sdk.KeyOwn, FirstSeen: seen}}); !strings.HasPrefix(got, "yours, since ") {
		t.Errorf("own: %q", got)
	}
}
