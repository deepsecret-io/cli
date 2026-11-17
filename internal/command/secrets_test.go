// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/deepsecret-io/deepsecret-go/secrets"
	"gopkg.in/yaml.v3"

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

// --format json and yaml print values from the server and from senders.
// On a terminal the characters that would act on it or reorder what is
// read are written as escapes, and the output still decodes to the same
// values. Redirected, it is what the encoder wrote, byte for byte.
func TestStructuredOutputOnATerminal(t *testing.T) {
	// U+009B starts a terminal command as ESC [ does, U+202E reverses the
	// text after it, U+E0001 is a formatting mark outside the BMP, and
	// U+200D joins an emoji and stays.
	hostile := "db\u009b31m.env \u202egnp.exe\u007f \U000E0001 \u0085 👩\u200d💻"
	data := map[string]any{
		"secrets": []map[string]string{{"name": hostile, "sender": "alice@example.com"}, {"name": "plain\nlines", hostile: "key"}},
		// YAML would write this one unquoted, where an escape is not read.
		"team":  "gnp.\u202eexe",
		"total": 2,
	}
	raw := func(out []byte) bool { return bytes.ContainsFunc(out, actsOnTerminal) }

	plainJSON, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	plainYAML, err := yaml.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	for format, plain := range map[string][]byte{"json": append(plainJSON, '\n'), "yaml": plainYAML} {
		piped, err := formatStructured(format, data, false)
		if err != nil || !bytes.Equal(piped, plain) {
			t.Errorf("%s redirected is not what the encoder wrote: %v\n%s", format, err, piped)
		}
		shown, err := formatStructured(format, data, true)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if raw(shown) {
			t.Errorf("%s on a terminal holds a raw control or formatting character:\n%q", format, shown)
		}
		if !bytes.Contains(shown, []byte("\u200d")) {
			t.Errorf("%s on a terminal lost the emoji joiner:\n%q", format, shown)
		}
		var want, got any
		decode := json.Unmarshal
		if format == "yaml" {
			decode = yaml.Unmarshal
		}
		if err := decode(plain, &want); err != nil {
			t.Fatal(err)
		}
		if err := decode(shown, &got); err != nil {
			t.Fatalf("%s on a terminal does not decode: %v\n%s", format, err, shown)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s on a terminal decodes to %v, want %v", format, got, want)
		}

		// Output with nothing to escape is the same on a terminal.
		safe := map[string]any{"name": "db.env", "note": "two\nlines"}
		piped, _ = formatStructured(format, safe, false)
		shown, _ = formatStructured(format, safe, true)
		if len(shown) == 0 || !bytes.Equal(piped, shown) {
			t.Errorf("%s without such characters differs on a terminal:\n%s\n%s", format, piped, shown)
		}
	}
	if !raw(plainJSON) {
		t.Fatal("the JSON encoder escaped everything itself: the test data proves nothing")
	}
	if out, err := formatStructured("table", data, true); out != nil || err != nil {
		t.Errorf("another format: %q, %v", out, err)
	}
}

// The server gives a list a page at a time. listAll asks for every page,
// whatever page size the server applies, and ends on the server's total or
// on an empty page.
func TestListAllFetchesEveryPage(t *testing.T) {
	for _, tc := range []struct {
		name               string
		have, serverPage   int
		reportedTotal      int
		wantLen, wantCalls int
	}{
		{"one short page", 7, 100, 7, 7, 1},
		{"several pages", 250, 100, 250, 250, 3},
		{"a server with smaller pages", 250, 50, 250, 250, 5},
		{"a total larger than the list", 120, 100, 500, 120, 3},
		{"nothing", 0, 100, 0, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			fetch := func(_ context.Context, opts ...secrets.ListOptions) ([]secrets.Info, int, error) {
				calls++
				opt := opts[0]
				if opt.Limit != listPageSize || opt.Email != "bob@example.com" {
					t.Errorf("asked with %+v", opt)
				}
				n := min(tc.serverPage, opt.Limit, max(tc.have-opt.Offset, 0))
				return make([]secrets.Info, n), tc.reportedTotal, nil
			}
			got, err := listAll(context.Background(), fetch, "bob@example.com")
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != tc.wantLen || calls != tc.wantCalls {
				t.Errorf("got %d secrets in %d calls, want %d in %d", len(got), calls, tc.wantLen, tc.wantCalls)
			}
		})
	}
}
