// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/deepsecret-io/deepsecret-go/secrets"

	"github.com/deepsecret-io/cli/internal/testutil"
	"github.com/deepsecret-io/cli/internal/ui"
)

// listed builds a secret sent by sender to recipients, updated at the
// given hour.
func listed(id, sender string, hour int, recipients ...string) secrets.Info {
	s := secrets.Info{
		ID:          id,
		SenderID:    sender,
		SenderEmail: sender + "@example.com",
		UpdatedAt:   time.Date(2026, 10, 30, hour, 0, 0, 0, time.UTC),
	}
	for _, r := range recipients {
		s.Recipients = append(s.Recipients, secrets.SecretRecipient{ID: r, Email: r + "@example.com"})
	}
	return s
}

func ids(list []secrets.Info) []string {
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
	received := []secrets.Info{toMeAndBob, selfOnly, fromBob}
	sent := []secrets.Info{toMeAndBob, selfOnly, toBob, dismissedSelfOnly}

	cases := []struct {
		name string
		got  []secrets.Info
		want []string
	}{
		{"inbox", inboxSecrets(received, sent, ""), []string{"to-me-and-bob", "self-only", "from-bob", "dismissed-self-only"}},
		{"inbox from bob", inboxSecrets([]secrets.Info{fromBob}, sent, "bob@example.com"), []string{"from-bob"}},
		{"inbox from me", inboxSecrets([]secrets.Info{toMeAndBob, selfOnly}, sent, "ME@example.com"), []string{"to-me-and-bob", "self-only", "dismissed-self-only"}},
		{"inbox empty", inboxSecrets(nil, nil, ""), []string{}},
		{"sent", sentSecrets(sent), []string{"to-me-and-bob", "to-bob"}},
	}
	for _, c := range cases {
		if got := ids(c.got); !slices.Equal(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// Describe lists a revision's files by name and size. The server keeps no
// hash of a file's content, and describe shows none, also when a server
// still sends one.
func TestDescribeFilesMetaShowsNoHash(t *testing.T) {
	const hash = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	var files []secrets.FileMeta
	if err := json.Unmarshal([]byte(`[{"name":"notes.txt","size":5,"sha256":"`+hash+`"}]`), &files); err != nil {
		t.Fatal(err)
	}

	var b strings.Builder
	writeFilesMeta(&b, files)
	out := b.String()

	for _, want := range []string{"Files Meta:", "notes.txt", "Size:"} {
		if !strings.Contains(out, want) {
			t.Errorf("the files list lacks %q:\n%s", want, out)
		}
	}
	for _, hidden := range []string{hash, "SHA256"} {
		if strings.Contains(out, hidden) {
			t.Errorf("the files list shows %q:\n%s", hidden, out)
		}
	}

	b.Reset()
	writeFilesMeta(&b, nil)
	if b.Len() != 0 {
		t.Errorf("no files, but the list printed %q", b.String())
	}
}

// An IP lock the secret's organization enforces comes from the API without
// addresses, which only the organization's admins see. It still reads as
// an IP lock, set by the organization, and not as no lock at all. A lock
// the sender set lists its addresses, and no lock reads as none.
func TestIPLockSummary(t *testing.T) {
	for _, c := range []struct {
		name, source string
		allowed      []string
		want         string
	}{
		{"enforced by the organization", "org-enforced", nil, "set by the organization (addresses not shown)"},
		{"set by the sender", "sender-set", []string{"10.0.0.0/8", "192.0.2.7"}, "10.0.0.0/8, 192.0.2.7"},
		{"no lock", "", nil, ""},
	} {
		if got := ipLockSummary(c.source, c.allowed); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// The policies of a secret as the API sends them: an IP lock its
// organization enforces comes with its source and no addresses.
var ipLockCases = []struct {
	name, api, want string
}{
	{"enforced by the organization", `{"ip_lock_source":"org-enforced"}`, "set by the organization (addresses not shown)"},
	{"set by the sender", `{"ip_lock_source":"sender-set","allowed_ips":["10.0.0.0/8","192.0.2.7"]}`, "10.0.0.0/8, 192.0.2.7"},
	{"no lock", `{}`, ""},
}

// describe shows an IP lock the organization enforces as an IP lock, set
// by the organization and without addresses, instead of leaving the line
// out as it does for a secret with no lock.
func TestDescribeShowsAnOrgEnforcedIPLock(t *testing.T) {
	for _, c := range ipLockCases {
		var s secrets.Info
		if err := json.Unmarshal([]byte(c.api), &s); err != nil {
			t.Fatal(err)
		}
		want := ""
		if c.want != "" {
			want = fmt.Sprintf("%-30s%s\n", "IP Lock:", c.want)
		}
		var b strings.Builder
		writeIPLock(&b, s)
		if got := b.String(); got != want {
			t.Errorf("%s: describe prints %q, want %q", c.name, got, want)
		}
	}
}

// After an update, policy shows an IP lock the organization enforces as
// set by the organization, and says "none" only when there is no lock.
func TestPolicyShowsAnOrgEnforcedIPLock(t *testing.T) {
	for _, c := range ipLockCases {
		var updated secrets.PolicyResult
		if err := json.Unmarshal([]byte(c.api), &updated); err != nil {
			t.Fatal(err)
		}
		want := "IP Lock " + c.want
		if c.want == "" {
			want = "IP Lock none"
		}
		out := testutil.AnsiEscape.ReplaceAllString(testutil.StderrOf(t, func() { printPolicies(&updated) }), "")
		if got := strings.Join(strings.Fields(out), " "); !strings.HasSuffix(got, want) || !strings.HasPrefix(got, "TTL none") {
			t.Errorf("%s: policy prints %q, want it to end with %q", c.name, got, want)
		}
	}
}

// list shows a default name whole, random suffix included: cut short, two
// sends without a name would read as one.
func TestListShowsADefaultNameWhole(t *testing.T) {
	now := time.Date(2026, 11, 14, 10, 15, 0, 0, time.UTC)
	for _, kind := range []string{"message", "secret"} {
		name := defaultName(kind, now)
		if got := ui.Ellipsis(name, listNameWidth); got != name {
			t.Errorf("list shows the default name %q as %q", name, got)
		}
	}
}

// list and describe show times in the local zone, as decrypt shows the
// signing time; text that is not a time is shown as it came.
func TestDisplayTime(t *testing.T) {
	saved := time.Local
	time.Local = time.FixedZone("+03", 3*3600)
	t.Cleanup(func() { time.Local = saved })
	at := time.Date(2026, 11, 16, 21, 10, 21, 502079000, time.UTC)
	if got := displayTime(at); got != "2026-11-17 00:10:21 +03" {
		t.Errorf("displayTime = %q", got)
	}
	for in, want := range map[string]string{
		"2026-11-16T21:10:21.502079Z": "2026-11-17 00:10:21 +03",
		"2026-11-16T21:10:21Z":        "2026-11-17 00:10:21 +03",
		"soon":                        "soon",
		"":                            "",
	} {
		if got := displayTimeString(in); got != want {
			t.Errorf("displayTimeString(%q) = %q, want %q", in, got, want)
		}
	}
}
