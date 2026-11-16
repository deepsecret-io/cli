// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package errs

import (
	"errors"
	"fmt"
	"testing"
)

// An error's first line, with a capital, is the summary; the rest of its
// message and the detail it carries are the detail.
func TestDescribeError(t *testing.T) {
	err := WithDetail(fmt.Errorf("upload interrupted: %w", errors.New("connection reset\n  after 3 attempts")), "The upload can resume:\n  secret resume 7da383f1")
	summary, detail := Describe(err)
	if summary != "Upload interrupted: connection reset" {
		t.Errorf("summary %q", summary)
	}
	if detail != "after 3 attempts\n\nThe upload can resume:\n  secret resume 7da383f1" {
		t.Errorf("detail %q", detail)
	}
}

// The summary starts with a capital only when its first word is a word:
// an email, an ID, a path or a quoted name keeps the case it was given.
func TestDescribeKeepsIdentifiersAsWritten(t *testing.T) {
	for in, want := range map[string]string{
		"team \"sre\" has no members to send to":        "Team \"sre\" has no members to send to",
		"alaa.q@example.com is your own account":        "alaa.q@example.com is your own account",
		"b3a846a0 has no pending upload":                "b3a846a0 has no pending upload",
		"./04a0b4f6 is a link":                          "./04a0b4f6 is a link",
		"--dir out is a link":                           "--dir out is a link",
		"\"empty\" has no members":                      "\"empty\" has no members",
		"could not fetch your account: connection lost": "Could not fetch your account: connection lost",
	} {
		if got, _ := Describe(errors.New(in)); got != want {
			t.Errorf("Describe(%q) = %q, want %q", in, got, want)
		}
	}
}
