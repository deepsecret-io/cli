// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package console writes to the terminal at the lowest level: ANSI styles,
// terminal detection, neutralizing outside values, and the live view on
// stderr. It knows nothing about DeepSecret.
package console

import (
	"fmt"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/term"
)

// EscapeControls writes control characters, invisible formatting marks
// and invalid UTF-8 in b as escapes, keeping newlines and tabs, and counts
// what it escaped.
func EscapeControls(b []byte) ([]byte, int) {
	var out []byte
	escaped := 0
	for len(b) > 0 {
		r, n := utf8.DecodeRune(b)
		switch {
		case r == utf8.RuneError && n <= 1:
			out = fmt.Appendf(out, "\\x%02x", b[0])
			escaped++
		case r == '\n' || r == '\t':
			out = append(out, b[:n]...)
		case unicode.IsControl(r) || (unicode.Is(unicode.Cf, r) && r != '\u200d'):
			if r < 0x100 {
				out = fmt.Appendf(out, "\\x%02x", r)
			} else {
				out = fmt.Appendf(out, "\\u%04x", r)
			}
			escaped++
		default:
			out = append(out, b[:n]...)
		}
		b = b[n:]
	}
	return out, escaped
}

// ── ANSI colors (no external deps) ─────────────────────────────────────────

// Styles for stderr, where all colored output goes. They are empty when
// color is off: NO_COLOR is set (https://no-color.org), TERM is "dumb",
// stderr is not a terminal (redirected to a file or a pipe), or the
// Windows console cannot show them.
var (
	Reset   = "\033[0m"
	Bold    = "\033[1m"
	Dim     = "\033[2m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Cyan    = "\033[36m"
	White   = "\033[37m"
	BoldRed = "\033[1;31m"
)

// StderrIsTerminal says whether stderr is an interactive terminal. Live
// progress, which redraws in place, is only drawn there.
var StderrIsTerminal = term.IsTerminal(int(os.Stderr.Fd()))

// LiveCursor says whether stderr takes ANSI escapes, so the live view can
// move the cursor to redraw several lines: a terminal, not TERM=dumb, and
// on Windows a console that turned them on.
var LiveCursor bool

// StdoutIsTerminal says whether decrypted content printed to stdout lands
// on a terminal, where control characters in it would be acted on.
var StdoutIsTerminal = term.IsTerminal(int(os.Stdout.Fd()))

func init() {
	LiveCursor = StderrIsTerminal && os.Getenv("TERM") != "dumb" && enableTerminalEscapes()
	if !LiveCursor || os.Getenv("NO_COLOR") != "" {
		Reset, Bold, Dim, Red, Green = "", "", "", "", ""
		Yellow, Cyan, White, BoldRed = "", "", "", ""
	}
}

// Safe makes a value from outside the CLI (the server, a payload, another
// person) safe to print on one line: control characters, including the
// escape that starts terminal commands, invalid UTF-8 and invisible
// formatting marks such as a right-to-left override show as "?", so the
// value cannot send the terminal commands, move the cursor, recolor or
// rewrite earlier output, or reorder what is read.
func Safe(s string) string { return sanitize(s, false) }

// SafeLines is safe for text that may span lines: newlines and tabs stay.
func SafeLines(s string) string { return sanitize(s, true) }

func sanitize(s string, lines bool) string {
	unsafe := func(r rune) bool {
		if lines && (r == '\n' || r == '\t') {
			return false
		}
		return r == utf8.RuneError || unicode.IsControl(r) || (unicode.Is(unicode.Cf, r) && r != '\u200d')
	}
	if utf8.ValidString(s) && !strings.ContainsFunc(s, unsafe) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if unsafe(r) {
			return '?'
		}
		return r
	}, s)
}
