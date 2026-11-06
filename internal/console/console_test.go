// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package console

import (
	"testing"
)

// Values from the server or a payload print on one line without control
// characters, escapes or invisible formatting, so they cannot send the
// terminal commands or rewrite what is on screen.
func TestSafeNeutralizesTerminalControl(t *testing.T) {
	for in, want := range map[string]string{
		"plain name":                        "plain name",
		"red\x1b[31mtext":                   "red?[31mtext",
		"title\x1b]0;pwned\x07":             "title?]0;pwned?",
		"clip\x1b]52;c;ZXZpbA==\x07":        "clip?]52;c;ZXZpbA==?",
		"over\rwrite":                       "over?write",
		"csi\u009b2J":                       "csi?2J",
		"invoice\u202efdp.exe":              "invoice?fdp.exe",
		"bad\xffutf8":                       "bad?utf8",
		"new\nline\ttab":                    "new?line?tab",
		"family \U0001F468\u200d\U0001F469": "family \U0001F468\u200d\U0001F469",
	} {
		if got := Safe(in); got != want {
			t.Errorf("Safe(%q) = %q, want %q", in, got, want)
		}
	}
	if got := SafeLines("line one\nline\ttwo\x1b[2J"); got != "line one\nline\ttwo?[2J" {
		t.Errorf("SafeLines kept or dropped the wrong characters: %q", got)
	}
}

// Decrypted content printed to a terminal shows control characters
// escaped, and keeps everything else as it is.
func TestEscapeControlsInDecryptedOutput(t *testing.T) {
	out, n := EscapeControls([]byte("KEY=val\x1b]52;c;ZXZpbA==\x07\nnext\tline\r\xff\u202e"))
	want := `KEY=val\x1b]52;c;ZXZpbA==\x07` + "\nnext\tline" + `\x0d\xff\u202e`
	if string(out) != want || n != 5 {
		t.Errorf("escapeControls = %q (%d escaped), want %q (5)", out, n, want)
	}
	if out, n := EscapeControls([]byte("héllo\n")); string(out) != "héllo\n" || n != 0 {
		t.Errorf("clean text changed: %q, %d", out, n)
	}
}
