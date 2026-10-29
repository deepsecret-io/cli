// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"slices"
	"testing"
	"time"

	"github.com/deepsecret-io/sdk"
)

// listed builds a secret sent by sender to recipients, updated at the
// given hour.
func listed(id, sender string, hour int, recipients ...string) sdk.SecretInfo {
	s := sdk.SecretInfo{
		ID:          id,
		SenderID:    sender,
		SenderEmail: sender + "@example.com",
		UpdatedAt:   time.Date(2026, 10, 30, hour, 0, 0, 0, time.UTC),
	}
	for _, r := range recipients {
		s.Recipients = append(s.Recipients, sdk.SecretRecipient{ID: r, Email: r + "@example.com"})
	}
	return s
}

func ids(list []sdk.SecretInfo) []string {
	out := make([]string, len(list))
	for i, s := range list {
		out[i] = s.ID
	}
	return out
}

// The inbox lists the secrets received and the ones sent only to
// oneself, each once, newest first; Sent lists the rest of one's sends.
func TestInboxAndSentSecrets(t *testing.T) {
	fromBob := listed("from-bob", "bob", 9, "me")
	selfOnly := listed("self-only", "me", 11, "me")
	dismissedSelfOnly := listed("dismissed-self-only", "me", 8, "me")
	toBob := listed("to-bob", "me", 10, "bob")
	toMeAndBob := listed("to-me-and-bob", "me", 12, "me", "bob")

	// The received list holds the caller's own sends while they are a
	// recipient who has not dismissed them.
	received := []sdk.SecretInfo{toMeAndBob, selfOnly, fromBob}
	sent := []sdk.SecretInfo{toMeAndBob, selfOnly, toBob, dismissedSelfOnly}

	cases := []struct {
		name string
		got  []sdk.SecretInfo
		want []string
	}{
		{"inbox", inboxSecrets(received, sent, ""), []string{"to-me-and-bob", "self-only", "from-bob", "dismissed-self-only"}},
		{"inbox from bob", inboxSecrets([]sdk.SecretInfo{fromBob}, sent, "bob@example.com"), []string{"from-bob"}},
		{"inbox from me", inboxSecrets([]sdk.SecretInfo{toMeAndBob, selfOnly}, sent, "ME@example.com"), []string{"to-me-and-bob", "self-only", "dismissed-self-only"}},
		{"inbox empty", inboxSecrets(nil, nil, ""), []string{}},
		{"sent", sentSecrets(sent), []string{"to-me-and-bob", "to-bob"}},
	}
	for _, c := range cases {
		if got := ids(c.got); !slices.Equal(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
