// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package ui

import (
	"context"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/deepsecret-io/sdk"
	"github.com/deepsecret-io/sdk/api"

	"github.com/deepsecret-io/cli/internal/console"
	"github.com/deepsecret-io/cli/internal/logging"
	"github.com/deepsecret-io/cli/internal/testutil"
)

// columns is how many columns s takes on a terminal.
func columns(s string) int {
	return utf8.RuneCountInString(testutil.AnsiEscape.ReplaceAllString(s, ""))
}

func uploadFrame(conns []sdk.ConnectionStatus) liveFrame {
	return liveFrame{stage: "uploading", done: 40 << 20, total: 96 << 20, rate: 8 << 20, transfer: true,
		snap: sdk.TransferSnapshot{Started: true, Total: 96 << 20, Done: 40 << 20, Parts: 12, PartsDone: 3,
			Threads: 4, MaxThreads: 32, Connections: conns}}
}

// The live view shows the step, then the transfer's numbers, then a line
// for each connection moving a part: the part and how far, or a retry. A
// free connection, or one whose part is all moved, gets no line; the
// others keep their numbers.
func TestLiveLinesShowEachConnection(t *testing.T) {
	now := time.Now()
	lines := liveLines("secret: Uploading...", uploadFrame([]sdk.ConnectionStatus{
		{Part: 4, Size: 8 << 20, Moved: 2 << 20, Attempt: 1, Since: now.Add(-2 * time.Second)},
		{Part: 5, Size: 8 << 20, Attempt: 2, Waiting: true},
		{},
		{Part: 12, Size: 1 << 20, Moved: 1 << 19, Attempt: 3, Since: now.Add(-time.Second)},
		{Part: 7, Size: 8 << 20, Moved: 8 << 20, Attempt: 1, Since: now.Add(-3 * time.Second)},
	}), now, 200, 40, true)
	if len(lines) != 5 {
		t.Fatalf("%d lines:\n%s", len(lines), strings.Join(lines, "\n"))
	}
	for i, want := range []string{
		"secret: Uploading...",
		"  uploading 40.0 MiB/96.0 MiB 42%  8.0 MiB/s, 7s left  4 connections, up to 32",
		"1 part  4 of 12  █████░░░░░░░░░░░░░░░  2.0 MiB/8.0 MiB  1.0 MiB/s",
		"2 part  5 of 12  ░░░░░░░░░░░░░░░░░░░░  retrying, attempt 2 of 8",
		"4 part 12 of 12  ██████████░░░░░░░░░░  512.0 KiB/1.0 MiB  512.0 KiB/s  attempt 3 of 8",
	} {
		if got := testutil.AnsiEscape.ReplaceAllString(lines[i], ""); !strings.Contains(got, want) {
			t.Errorf("line %d: %q, want it to hold %q", i, got, want)
		}
	}
}

// No line is wider than the terminal, and connections that do not fit
// its height are counted on one line, so the view never scrolls or wraps.
func TestLiveLinesFitTheTerminal(t *testing.T) {
	now := time.Now()
	conns := make([]sdk.ConnectionStatus, 40)
	for i := range conns {
		conns[i] = sdk.ConnectionStatus{Part: i + 1, Size: 8 << 20, Moved: 3 << 20, Attempt: 1, Since: now.Add(-time.Minute)}
	}
	for _, width := range []int{1, 20, 50, 300} {
		lines := liveLines("secret: Uploading...", uploadFrame(conns), now, width, 10, true)
		if len(lines) != 9 || (width == 300 && strings.Count(strings.Join(lines, "\n"), "part ") != 6) {
			t.Fatalf("width %d: %d lines for a 10-row terminal", width, len(lines))
		}
		for _, l := range lines {
			if columns(l) > max(width-1, 1) {
				t.Fatalf("width %d: a line of %d columns: %q", width, columns(l), l)
			}
		}
		if width == 300 && !strings.Contains(lines[8], "and 34 more connections") {
			t.Fatalf("the last line: %q", lines[8])
		}
	}
}

// A terminal that cannot move the cursor gets one line, where a long label
// gives way to the numbers; a stage without a transfer has no connections.
func TestLiveLinesWithoutRows(t *testing.T) {
	now := time.Now()
	f := uploadFrame([]sdk.ConnectionStatus{{Part: 1, Size: 10, Attempt: 1}})
	head := "secret: Encrypting to /a/very/long/path/that/fills/the/line/report-2026.tar.cbor..."
	lines := liveLines(head, f, now, 100, 40, false)
	if len(lines) != 1 || columns(lines[0]) > 99 || !strings.HasPrefix(lines[0], "secret: Encrypting") ||
		!strings.Contains(lines[0], "...  uploading 40.0 MiB/96.0 MiB 42%  8.0 MiB/s, 7s left  4 connections, up to 32") {
		t.Fatalf("no cursor moves: %q", lines)
	}
	if lines := liveLines("head  ", f, now, 200, 40, false); lines[0] != "head  "+liveStats(f) {
		t.Fatalf("a short label: %q", lines)
	}
	f = liveFrame{stage: "encrypting", done: 5, total: 10}
	if lines := liveLines("head", f, now, 100, 40, true); len(lines) != 2 || !strings.Contains(lines[1], "encrypting 5 B/10 B 50%") {
		t.Fatalf("encrypting: %q", lines)
	}
}

// Encrypting goes from starting through its bytes; an upload is starting
// until its transfer begins; a stage with nothing after it stays at its
// end; decryption's stage follows its passes.
func TestLiveFrameStages(t *testing.T) {
	now := time.Now()
	p := NewStageProgress("encrypting")
	if f := p.frame(now); f.stage != "starting" || f.total != 0 {
		t.Fatalf("before: %+v", f)
	}
	p.Pre.Set(5, 10)
	if f := p.frame(now); f.stage != "encrypting" || f.done != 5 || f.total != 10 || f.transfer {
		t.Fatalf("encrypting: %+v", f)
	}
	if f := NewUploadProgress().frame(now); f.stage != "starting" || f.transfer {
		t.Fatalf("upload before its transfer: %+v", f)
	}

	r := NewStageProgress("reading")
	r.Pre.Set(10, 10)
	if f := r.frame(now); f.stage != "reading" || f.done != 10 || f.total != 10 {
		t.Fatalf("a finished stage with nothing after it: %+v", f)
	}

	d := NewStageProgress("decrypting")
	for _, pass := range []string{"checking", "checking the archive", "writing"} {
		d.Pre.SetStage(pass, 3, 12)
		if f := d.frame(now); f.stage != pass || f.done != 3 || f.total != 12 {
			t.Fatalf("pass %q: %+v", pass, f)
		}
	}
	if f := NewDownloadProgress().frame(now); f.stage != "starting" || f.transfer {
		t.Fatalf("download before it starts: %+v", f)
	}
}

// The rate is over the last seconds of a stage, and starts over with the
// next stage.
func TestRateMeter(t *testing.T) {
	var m rateMeter
	t0 := time.Now()
	if r := m.sample("uploading", 0, t0); r != 0 {
		t.Fatalf("one sample: %v", r)
	}
	m.sample("uploading", 10<<20, t0.Add(time.Second))
	if r := m.sample("uploading", 20<<20, t0.Add(2*time.Second)); r != 10<<20 {
		t.Fatalf("rate %v", r)
	}
	for i := 3; i <= 20; i++ {
		m.sample("uploading", 20<<20, t0.Add(time.Duration(i)*time.Second))
	}
	if r := m.sample("uploading", 20<<20, t0.Add(21*time.Second)); r != 0 {
		t.Fatalf("a stalled link still shows %v", r)
	}
	if r := m.sample("finishing", 20<<20, t0.Add(22*time.Second)); r != 0 {
		t.Fatalf("a new stage: %v", r)
	}
}

// A step's label can hold a secret's name, from outside the CLI: its lines
// show it without its control characters.
func TestStepLinesNeutralizeTheLabel(t *testing.T) {
	out := testutil.StderrOf(t, func() {
		_ = RunPipeline(context.Background(), "upload", []Step{{Label: "Uploading evil\033]0;owned\a\033[2J", Done: "Upload complete", Action: func() (string, error) {
			return "id=evil\033[2J", nil
		}}})
	})
	if strings.Contains(out, "\033]") || strings.Contains(out, "\a") || !strings.Contains(out, "Uploading evil?]0;owned??[2J...") || !strings.Contains(out, "[id=evil?[2J]") {
		t.Fatalf("%q", out)
	}
}

// Progress shows only with --progress: by default a transfer prints its
// step line and nothing else, on a terminal or not, so pipes, scripts and
// logs see plain lines. With it, a terminal gets the live view, and
// redirected output a plain line now and then, never a redraw.
func TestProgressOnlyWithTheFlag(t *testing.T) {
	savedProgress, savedTerminal, savedCursor, savedEvery := ShowProgress, console.StderrIsTerminal, console.LiveCursor, progressLogEvery
	t.Cleanup(func() {
		ShowProgress, console.StderrIsTerminal, console.LiveCursor, progressLogEvery = savedProgress, savedTerminal, savedCursor, savedEvery
	})
	progressLogEvery = 150 * time.Millisecond
	run := func() string {
		return testutil.StderrOf(t, func() {
			p := NewStageProgress("encrypting")
			err := RunPipeline(context.Background(), "secret", []Step{{Label: "Encrypting", Done: "Encryption complete", Live: p, Action: func() (string, error) {
				p.Pre.Set(1<<20, 4<<20)
				time.Sleep(700 * time.Millisecond)
				return "", nil
			}}})
			if err != nil {
				t.Error(err)
			}
		})
	}
	redraw := func(s string) bool { return strings.ContainsAny(s, "\r\033") }

	for _, terminal := range []bool{false, true} {
		ShowProgress, console.StderrIsTerminal, console.LiveCursor = false, terminal, terminal
		if out := run(); redraw(out) || !strings.HasPrefix(out, "secret: Encrypting...\nsecret: Encryption complete after ") || strings.Count(out, "\n") != 2 {
			t.Fatalf("by default (terminal %v) stderr got %q, want only the step's start and done lines", terminal, out)
		}
	}

	ShowProgress, console.StderrIsTerminal, console.LiveCursor = true, true, true
	if out := run(); !strings.Contains(out, "\033[J") || !strings.Contains(out, "encrypting 1.0 MiB/4.0 MiB 25%") {
		t.Fatalf("--progress on a terminal got %q, want the live view redrawn", out)
	}

	ShowProgress, console.StderrIsTerminal, console.LiveCursor = true, false, false
	out := run()
	if redraw(out) || !strings.Contains(out, "secret: Encrypting...  encrypting 1.0 MiB/4.0 MiB 25%\n") {
		t.Fatalf("--progress redirected got %q, want plain progress lines", out)
	}
}

// A log line printed while the live view is shown goes above it, and the
// view is drawn again straight below, so --debug lines scroll above a
// progress view that stays at the bottom instead of mixing with it. A step
// that ends clears the view, and later log lines do not bring it back.
func TestLogLinesPrintAboveTheLiveView(t *testing.T) {
	savedCursor, savedLogger := console.LiveCursor, logging.Log
	console.LiveCursor = true
	t.Cleanup(func() {
		console.LiveCursor, logging.Log = savedCursor, savedLogger
		console.WithLiveCleared(func() {})
	})
	t.Setenv("DS_LOG", "")
	t.Setenv("DS_LOG_PATH", "")
	if err := logging.Setup(true); err != nil {
		t.Fatal(err)
	}
	view := []string{"secret: Downloading...", "  downloading 1.0 MiB/4.0 MiB 25%", "  1 part 2 of 4"}
	out := testutil.StderrOf(t, func() {
		console.DrawLive(view)
		api.Module(logging.Log, "range").Debug("piece 3 split")
	})
	line := strings.Index(out, "piece 3 split")
	if line < 0 {
		t.Fatalf("no debug line in %q", out)
	}
	// The view is erased before the line and drawn whole after it.
	if erase := strings.Index(out, "\r\033[2A\033[J"); erase < 0 || erase > line {
		t.Fatalf("the view was not erased before the debug line: %q", out)
	}
	if !strings.HasSuffix(out, strings.Join(view, "\n")) {
		t.Fatalf("the view was not drawn again below the debug line: %q", out)
	}
	if console.LiveHeight() != len(view) {
		t.Fatalf("live view height = %d, want %d", console.LiveHeight(), len(view))
	}

	out = testutil.StderrOf(t, func() {
		console.WithLiveCleared(func() {})
		api.Module(logging.Log, "decrypt").Debug("after the step")
	})
	if strings.Contains(out, view[0]) || console.LiveHeight() != 0 {
		t.Fatalf("the view came back after the step ended: %q (%d lines)", out, console.LiveHeight())
	}
}
