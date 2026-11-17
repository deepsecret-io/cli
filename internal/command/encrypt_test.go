// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"bytes"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/deepsecret-io/cli/internal/errs"
	"github.com/deepsecret-io/cli/internal/flags"
)

// A send under the name of a secret the sender has adds a revision to that
// secret. So two sends without a name get different names, also within one
// second, and each name is one the CLI and the protocol accept: here
// letters, digits and hyphens only.
func TestDefaultNameIsUniquePerSend(t *testing.T) {
	now := time.Date(2026, 11, 14, 10, 15, 0, 0, time.UTC)
	for kind, pattern := range map[string]*regexp.Regexp{
		"message": regexp.MustCompile(`^message-20261114-101500-[0-9a-f]{6}$`),
		"secret":  regexp.MustCompile(`^secret-20261114-101500-[0-9a-f]{6}$`),
	} {
		first, second := defaultName(kind, now), defaultName(kind, now)
		if first == second {
			t.Errorf("two %s sends in one second are both named %q", kind, first)
		}
		for _, name := range []string{first, second} {
			if !pattern.MatchString(name) {
				t.Errorf("default name %q does not match %s", name, pattern)
			}
			var accepted string
			if err := flags.NewName(&accepted).Set(name); err != nil {
				t.Errorf("default name %q is not a valid --name: %v", name, err)
			}
		}
	}
}

// The Files line of an archived send counts its regular files, and its
// entries when folders or links add to them.
func TestArchivedFiles(t *testing.T) {
	for _, tc := range []struct {
		files, entries int
		want           string
	}{
		{1880, 2208, "1880 in one archive (2208 entries with folders and links)"},
		{12, 12, "12 in one archive"},
		{0, 1, "1 entry in one archive"},
		{0, 5, "5 entries in one archive"},
	} {
		if got := archivedFiles(tc.files, tc.entries); got != tc.want {
			t.Errorf("archivedFiles(%d, %d) = %q, want %q", tc.files, tc.entries, got, tc.want)
		}
	}
}

// endless is input that never ends, and counts what was read of it.
type endless struct{ read int }

func (e *endless) Read(p []byte) (int, error) {
	e.read += len(p)
	return len(p), nil
}

// The SDK refuses to decrypt a message or key-value data over 16 MiB, so
// one that large is refused before it is sent, with the way to send it: as
// a file. Text up to the limit is read whole, and input without an end is
// read one byte past the limit and no further.
func TestMessageAndDataAreCappedAtWhatDecrypts(t *testing.T) {
	const limit = maxSmallPayload - payloadEnvelope
	if got, err := readMessage(bytes.NewReader(make([]byte, limit))); err != nil || len(got) != limit {
		t.Fatalf("a message at the limit: %d bytes, %v", len(got), err)
	}
	for name, r := range map[string]io.Reader{
		"one byte over": bytes.NewReader(make([]byte, limit+1)),
		"endless":       &endless{},
	} {
		got, err := readMessage(r)
		if err == nil {
			t.Fatalf("%s: read %d bytes as a message", name, len(got))
		}
		if summary, detail := errs.Describe(err); !strings.Contains(summary, "is over 16.0 MiB") || !strings.Contains(detail, "as a file") {
			t.Errorf("%s: %q, %q", name, summary, detail)
		}
		// io.ReadAll may ask for more than is left of the limit, but never
		// takes more than one byte past it.
		if e, ok := r.(*endless); ok && e.read > 2*maxSmallPayload {
			t.Errorf("read %d bytes of endless input", e.read)
		}
	}

	if err := checkDataSize([]string{"DB_PASS=secret", "API_KEY=abc"}); err != nil {
		t.Errorf("small pairs: %v", err)
	}
	half := "K=" + strings.Repeat("v", maxSmallPayload/2)
	if err := checkDataSize([]string{half}); err != nil {
		t.Errorf("one pair of half the limit: %v", err)
	}
	err := checkDataSize([]string{half, half})
	if err == nil {
		t.Fatal("pairs over the limit together were accepted")
	}
	if _, detail := errs.Describe(err); !strings.Contains(detail, "as a file") {
		t.Errorf("detail %q", detail)
	}
}

// --archive hides file names from the server, which sees the secret's
// name: so without -n that name is a generic one, not the first input's.
// Without --archive it is still the first input's name.
func TestSendName(t *testing.T) {
	now := time.Date(2026, 11, 14, 10, 15, 0, 0, time.UTC)
	generic := regexp.MustCompile(`^secret-20261114-101500-[0-9a-f]{6}$`)
	inputs := []string{filepath.Join("clients", "acme-payroll.env"), "other.env"}
	for _, in := range [][]string{inputs[:1], inputs} {
		if got := sendName(in, true, false, now); !generic.MatchString(got) {
			t.Errorf("--archive of %v is named %q", in, got)
		}
	}
	if got := sendName(inputs[:1], false, false, now); got != "acme-payroll.env" {
		t.Errorf("one file: %q", got)
	}
	if got := sendName(inputs, false, false, now); got != "acme-payroll.env (2 files)" {
		t.Errorf("two files: %q", got)
	}
	if got := sendName(nil, false, true, now); !strings.HasPrefix(got, "message-") {
		t.Errorf("a message: %q", got)
	}
	if got := sendName(nil, false, false, now); !generic.MatchString(got) {
		t.Errorf("key-value data: %q", got)
	}
}
