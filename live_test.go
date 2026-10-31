// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"context"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/deepsecret-io/sdk"
)

var ansiEscape = regexp.MustCompile("\033\\[[0-9;]*[A-Za-z]")

// columns is how many columns s takes on a terminal.
func columns(s string) int { return utf8.RuneCountInString(ansiEscape.ReplaceAllString(s, "")) }

func uploadFrame(conns []sdk.ConnectionStatus) liveFrame {
	return liveFrame{stage: "uploading", done: 40 << 20, total: 96 << 20, rate: 8 << 20, transfer: true,
		snap: sdk.TransferSnapshot{Started: true, Total: 96 << 20, Done: 40 << 20, Parts: 12, PartsDone: 3,
			Threads: 4, MaxThreads: 32, Connections: conns}}
}

// The live view shows the step, then the transfer's numbers, then one
// line per connection: the part it moves and how far, a retry, or that it
// is free.
func TestLiveLinesShowEachConnection(t *testing.T) {
	now := time.Now()
	lines := liveLines("ds.encrypt_upload: Encrypting locally, then uploading", uploadFrame([]sdk.ConnectionStatus{
		{Part: 4, Size: 8 << 20, Moved: 2 << 20, Attempt: 1, Since: now.Add(-2 * time.Second)},
		{Part: 5, Size: 8 << 20, Attempt: 2, Waiting: true},
		{},
		{Part: 12, Size: 1 << 20, Moved: 1 << 19, Attempt: 3, Since: now.Add(-time.Second)},
	}), now, 200, 40, true)
	if len(lines) != 6 {
		t.Fatalf("%d lines:\n%s", len(lines), strings.Join(lines, "\n"))
	}
	for i, want := range []string{
		"ds.encrypt_upload: Encrypting locally, then uploading",
		"  uploading 40.0 MB/96.0 MB 42%  8.0 MB/s, 7s left  4 connections, up to 32",
		"1 part  4 of 12  █████░░░░░░░░░░░░░░░  2.0 MB/8.0 MB  1.0 MB/s",
		"2 part  5 of 12  ░░░░░░░░░░░░░░░░░░░░  retrying, attempt 2 of 8",
		"3 free",
		"4 part 12 of 12  ██████████░░░░░░░░░░  512.0 KB/1.0 MB  512.0 KB/s  attempt 3 of 8",
	} {
		if got := ansiEscape.ReplaceAllString(lines[i], ""); !strings.Contains(got, want) {
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
		lines := liveLines("ds.encrypt_upload: Encrypting locally, then uploading", uploadFrame(conns), now, width, 10, true)
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
	head := "ds.encrypt: Encrypting to /a/very/long/path/that/fills/the/line/report-2026.tar.cbor      "
	lines := liveLines(head, f, now, 100, 40, false)
	if len(lines) != 1 || columns(lines[0]) > 99 || !strings.HasPrefix(lines[0], "ds.encrypt: Encrypt") ||
		!strings.Contains(lines[0], "...  uploading 40.0 MB/96.0 MB 42%  8.0 MB/s, 7s left  4 connections, up to 32") {
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

// A send goes from starting, through encrypting, to setting up the
// upload; a stage with nothing after it stays at its end; decryption's
// stage follows its passes.
func TestLiveFrameStages(t *testing.T) {
	now := time.Now()
	p := newSendProgress()
	if f := p.frame(now); f.stage != "starting" || f.total != 0 {
		t.Fatalf("before: %+v", f)
	}
	p.pre.set(5, 10)
	if f := p.frame(now); f.stage != "encrypting" || f.done != 5 || f.total != 10 || f.transfer {
		t.Fatalf("encrypting: %+v", f)
	}
	p.pre.set(10, 10)
	if f := p.frame(now); f.stage != "starting the upload" {
		t.Fatalf("encrypted: %+v", f)
	}

	r := newStageProgress("reading")
	r.pre.set(10, 10)
	if f := r.frame(now); f.stage != "reading" || f.done != 10 || f.total != 10 {
		t.Fatalf("a finished stage with nothing after it: %+v", f)
	}

	d := newStageProgress("decrypting")
	for _, pass := range []string{"checking", "checking the archive", "writing"} {
		d.pre.setStage(pass, 3, 12)
		if f := d.frame(now); f.stage != pass || f.done != 3 || f.total != 12 {
			t.Fatalf("pass %q: %+v", pass, f)
		}
	}
	if f := newDownloadProgress().frame(now); f.stage != "starting" || f.transfer {
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

// fit cuts at the terminal's width in columns: escapes take none, and a
// multibyte rune takes one.
func TestFit(t *testing.T) {
	if got := fit("\033[36mabcdef\033[0m", 4); ansiEscape.ReplaceAllString(got, "") != "abc" {
		t.Fatalf("%q", got)
	}
	if got := fit("█████", 3); got != "██"+ansiReset {
		t.Fatalf("%q", got)
	}
	if got := fit("short", 80); got != "short" {
		t.Fatalf("%q", got)
	}
	if got := cut("\033[1mabcdefghij\033[0m", 7); ansiEscape.ReplaceAllString(got, "") != "abcd..." {
		t.Fatalf("%q", got)
	}
}

// A step's label can hold a secret's name, from outside the CLI: the live
// view shows it without its control characters.
func TestLiveHeadNeutralizesTheLabel(t *testing.T) {
	head := liveHead("ds.resume_upload", "Uploading evil\033]0;owned\a\033[2J", 0)
	if !strings.Contains(head, "Uploading evil?]0;owned??[2J") {
		t.Fatalf("%q", head)
	}
}

func TestFmtRemaining(t *testing.T) {
	for d, want := range map[time.Duration]string{
		7 * time.Second:                "7s",
		90 * time.Second:               "1m 30s",
		2*time.Hour + 5*time.Minute:    "2h 05m",
		59*time.Second + time.Second/2: "1m 00s",
	} {
		if got := fmtRemaining(d); got != want {
			t.Errorf("%v: %q, want %q", d, got, want)
		}
	}
}

// stderrOf runs f with stderr going to a pipe, and returns what it wrote.
func stderrOf(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stderr
	os.Stderr = w
	got := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		got <- string(b)
	}()
	f()
	os.Stderr = saved
	_ = w.Close()
	return <-got
}

// Progress shows only with --progress: by default a transfer prints its
// step line and nothing else, on a terminal or not, so pipes, scripts and
// logs see plain lines. With it, a terminal gets the live view, and
// redirected output a plain line now and then, never a redraw.
func TestProgressOnlyWithTheFlag(t *testing.T) {
	savedProgress, savedTerminal, savedCursor, savedCtx, savedEvery := showProgress, stderrIsTerminal, liveCursor, rootCtx, progressLogEvery
	t.Cleanup(func() {
		showProgress, stderrIsTerminal, liveCursor, rootCtx, progressLogEvery = savedProgress, savedTerminal, savedCursor, savedCtx, savedEvery
	})
	rootCtx, progressLogEvery = context.Background(), 150*time.Millisecond
	run := func() string {
		return stderrOf(t, func() {
			p := newStageProgress("encrypting")
			err := runPipeline("Encrypt", []step{{label: "Encrypting", live: p, action: func() (string, error) {
				p.pre.set(1<<20, 4<<20)
				time.Sleep(700 * time.Millisecond)
				return "", nil
			}}}, nil)
			if err != nil {
				t.Error(err)
			}
		})
	}
	redraw := func(s string) bool { return strings.ContainsAny(s, "\r\033") }

	for _, terminal := range []bool{false, true} {
		showProgress, stderrIsTerminal, liveCursor = false, terminal, terminal
		if out := run(); redraw(out) || strings.Count(out, "\n") != 1 || !strings.Contains(out, "Encrypting") {
			t.Fatalf("by default (terminal %v) stderr got %q, want only the step line", terminal, out)
		}
	}

	showProgress, stderrIsTerminal, liveCursor = true, true, true
	if out := run(); !strings.Contains(out, "\033[J") || !strings.Contains(out, "encrypting 1.0 MB/4.0 MB 25%") {
		t.Fatalf("--progress on a terminal got %q, want the live view redrawn", out)
	}

	showProgress, stderrIsTerminal, liveCursor = true, false, false
	out := run()
	if redraw(out) || !strings.Contains(out, "Encrypting  encrypting 1.0 MB/4.0 MB 25%\n") {
		t.Fatalf("--progress redirected got %q, want plain progress lines", out)
	}
}
