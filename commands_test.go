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

func TestEncryptRecipientFlags(t *testing.T) {
	cases := map[string]struct {
		args []string
		want string
	}{
		"to with group": {[]string{"-t", "a@example.com", "-g", "eng", "-d", "K=V"}, "either --to or --group"},
		"duplicate to":  {[]string{"-t", "a@example.com", "-t", "A@example.com", "-d", "K=V"}, "listed twice"},
		"invalid to":    {[]string{"-t", "nobody", "-d", "K=V"}, "invalid recipient email"},
	}
	for name, c := range cases {
		if err := runCmd(newEncryptCmd(), c.args...); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
}

func TestRevokeRequiresRecipient(t *testing.T) {
	id := "10000000-0000-4000-8000-000000000001"
	if err := runCmd(newRevokeCmd(), id); err == nil || !strings.Contains(err.Error(), "--to") {
		t.Errorf("no --to: %v", err)
	}
	if err := runCmd(newRevokeCmd(), "not-a-uuid", "-t", "a@example.com"); err == nil || !strings.Contains(err.Error(), "invalid secret ID") {
		t.Errorf("bad id: %v", err)
	}
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

// --local writes a file instead of sending, so the send-only flags are
// refused with it, and its own flags need it.
func TestLocalFlags(t *testing.T) {
	cases := map[string]struct {
		cmd  func() *cobra.Command
		args []string
		want string
	}{
		"local with ttl":        {newEncryptCmd, []string{"--local", "--ttl", "1h", "-d", "K=V"}, "--ttl applies to sends"},
		"local with ip":         {newEncryptCmd, []string{"--local", "--ip", "1.1.1.1", "-d", "K=V"}, "--ip applies to sends"},
		"local with threads":    {newEncryptCmd, []string{"--local", "--threads", "8", "-d", "K=V"}, "--threads applies to sends"},
		"output without local":  {newEncryptCmd, []string{"-o", "x.cbor", "-d", "K=V"}, "need --local"},
		"overwrite only":        {newEncryptCmd, []string{"--overwrite", "-d", "K=V"}, "need --local"},
		"decrypt local no file": {newDecryptCmd, []string{"--local"}, "provide the file"},
		"decrypt local missing": {newDecryptCmd, []string{"--local", "/nonexistent/x.cbor"}, "no such file"},
		"decrypt local dir":     {newDecryptCmd, []string{"--local", t.TempDir()}, "is not a file"},
		"decrypt local rev":     {newDecryptCmd, []string{"--local", "x.cbor", "--revision", "r"}, "--revision applies to secrets"},
	}
	for name, c := range cases {
		if err := runCmd(c.cmd(), c.args...); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
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
