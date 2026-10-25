// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"io"
	"strings"
	"testing"

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
