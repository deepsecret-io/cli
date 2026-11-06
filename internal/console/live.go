// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package console

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"unicode/utf8"

	"golang.org/x/term"
)

// Fit cuts s to width-1 columns, so a line never wraps, which would throw
// off the redraw.
func Fit(s string, width int) string { return Cut(s, max(width-1, 1)) }

// Cut shortens s to cols columns, ending it with "..." when there is room.
// ANSI escapes take no columns; every other rune takes one.
func Cut(s string, cols int) string {
	if VisibleCols(s) <= cols {
		return s
	}
	keep, mark := cols, ""
	if cols >= 4 {
		keep, mark = cols-3, "..."
	}
	n := 0
	for i := 0; i < len(s); {
		if s[i] == '\033' {
			i = escapeEnd(s, i)
			continue
		}
		if n == keep {
			return s[:i] + Reset + mark
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		i += size
		n++
	}
	return s
}

// VisibleCols is how many columns s takes on a terminal.
func VisibleCols(s string) int {
	n := 0
	for i := 0; i < len(s); {
		if s[i] == '\033' {
			i = escapeEnd(s, i)
			continue
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		i += size
		n++
	}
	return n
}

// escapeEnd is the index after the ANSI escape at s[i]: a CSI sequence,
// ESC [ through its final byte, or ESC and the byte after it.
func escapeEnd(s string, i int) int {
	j := i + 1
	if j >= len(s) || s[j] != '[' {
		return j + 1
	}
	j++
	for j < len(s) && (s[j] < 0x40 || s[j] > 0x7e) {
		j++
	}
	return j + 1
}

// ── The live view on screen ─────────────────────────────────────────────────

// live is the live view on stderr. Everything that writes to stderr while
// it may be shown holds mu, so a log line never lands inside it.
var live struct {
	mu    sync.Mutex
	lines int      // lines of the live view on screen; 0 when none
	last  []string // the view drawn last, put back under a line printed above it
}

// LiveHeight is how many lines of the live view are on screen; 0 when none.
func LiveHeight() int {
	live.mu.Lock()
	defer live.mu.Unlock()
	return live.lines
}

// Size is stderr's size, or 80 by 24 when it cannot be read.
func Size() (width, height int) {
	w, h, err := term.GetSize(int(os.Stderr.Fd()))
	if err != nil || w <= 0 || h <= 0 {
		return 80, 24
	}
	return w, h
}

// DrawLive replaces the live view with lines.
func DrawLive(lines []string) {
	live.mu.Lock()
	defer live.mu.Unlock()
	var b strings.Builder
	eraseLive(&b)
	b.WriteString(strings.Join(lines, "\n"))
	live.lines = len(lines)
	live.last = lines
	// A redraw that fails on stderr has nowhere to be reported.
	_, _ = io.WriteString(os.Stderr, b.String())
}

// WithLiveCleared removes the live view, if shown, and runs write, which
// writes to stderr. The view stays off until the next redraw: a step that
// ends uses it to leave no view behind.
func WithLiveCleared(write func()) {
	live.mu.Lock()
	defer live.mu.Unlock()
	if live.lines > 0 {
		var b strings.Builder
		eraseLive(&b)
		_, _ = io.WriteString(os.Stderr, b.String()) // as in DrawLive
	}
	live.last = nil
	write()
}

// AboveLive runs write, which writes whole lines to stderr, above the live
// view: the view, if shown, is removed and put straight back below them,
// so log lines scroll above a view that stays at the bottom.
func AboveLive(write func()) {
	live.mu.Lock()
	defer live.mu.Unlock()
	shown := live.lines > 0
	var b strings.Builder
	eraseLive(&b)
	_, _ = io.WriteString(os.Stderr, b.String()) // as in DrawLive
	write()
	if shown {
		_, _ = io.WriteString(os.Stderr, strings.Join(live.last, "\n"))
		live.lines = len(live.last)
	}
}

// eraseLive writes what removes the live view, leaving the cursor where
// its first line began. The caller holds live.mu.
func eraseLive(b *strings.Builder) {
	switch {
	case live.lines == 0:
		return
	case LiveCursor:
		b.WriteString("\r")
		if live.lines > 1 {
			fmt.Fprintf(b, "\033[%dA", live.lines-1)
		}
		b.WriteString("\033[J")
	default:
		width, _ := Size()
		b.WriteString("\r" + strings.Repeat(" ", max(width-1, 1)) + "\r")
	}
	live.lines = 0
}
