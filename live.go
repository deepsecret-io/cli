// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/term"

	"github.com/deepsecret-io/sdk"
)

// ── Live progress ───────────────────────────────────────────────────────────
//
// While a step encrypts, uploads or downloads, a live view on stderr shows
// how far it is: a head line with the stage, bytes, rate and time left,
// and under it one bar per connection of the transfer, with the part it
// moves. It is redrawn in place a few times a second, only on a terminal.
// A terminal that cannot move the cursor gets the head line alone.

// liveProgress is what a step reports for its live view.
type liveProgress struct {
	// verb names the transfer, like "uploading"; empty for a step
	// without one.
	verb string
	// transfer is passed to the SDK, which fills it in.
	transfer sdk.TransferStatus
	// pre is the stage before the transfer, or the step's only stage:
	// encrypting a send, reading a local file. between names the wait
	// after it, while the transfer is set up.
	pre     stageCounter
	between string

	rate rateMeter
}

// newSendProgress follows a send: encrypting, then uploading.
func newSendProgress() *liveProgress {
	return &liveProgress{verb: "uploading", pre: stageCounter{label: "encrypting"}, between: "starting the upload"}
}

// newUploadProgress follows an upload of ciphertext already sealed.
func newUploadProgress() *liveProgress { return &liveProgress{verb: "uploading"} }

// newDownloadProgress follows a download.
func newDownloadProgress() *liveProgress { return &liveProgress{verb: "downloading"} }

// newStageProgress follows a step without a transfer, like encrypting
// to a local file. Its stage can change label.
func newStageProgress(label string) *liveProgress {
	return &liveProgress{pre: stageCounter{label: label}}
}

// stageCounter is a stage's progress, as the SDK reports it. Its label
// can change, as decryption goes from pass to pass.
type stageCounter struct {
	mu          sync.Mutex
	label       string
	done, total int64
}

func (c *stageCounter) set(done, total int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.done, c.total = done, total
}

func (c *stageCounter) setStage(label string, done, total int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.label, c.done, c.total = label, done, total
}

func (c *stageCounter) read() (label string, done, total int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.label, c.done, c.total
}

// liveFrame is what the live view shows at one moment.
type liveFrame struct {
	stage       string
	done, total int64
	rate        float64 // bytes per second, 0 while unknown
	snap        sdk.TransferSnapshot
	transfer    bool // snap is a transfer in progress
}

// frame reads the step's progress now.
func (p *liveProgress) frame(now time.Time) liveFrame {
	f := liveFrame{stage: "starting"}
	snap := p.transfer.Snapshot()
	preLabel, preDone, preTotal := p.pre.read()
	switch {
	case snap.Started && snap.PartsDone >= snap.Parts:
		f.stage, f.done, f.total = "finishing", snap.Done, snap.Total
	case snap.Started:
		f.stage, f.done, f.total, f.snap, f.transfer = p.verb, snap.Done, snap.Total, snap, true
	case preTotal > 0 && preDone >= preTotal && p.between != "":
		f.stage = p.between
	case preTotal > 0:
		f.stage, f.done, f.total = preLabel, preDone, preTotal
	}
	f.rate = p.rate.sample(f.stage, f.done, now)
	return f
}

// rateMeter is a stage's rate over its last few seconds, which follows a
// changing link better than the average since the start.
type rateMeter struct {
	stage   string
	samples []rateSample
}

type rateSample struct {
	at   time.Time
	done int64
}

const rateWindow = 5 * time.Second

func (m *rateMeter) sample(stage string, done int64, now time.Time) float64 {
	if stage != m.stage {
		m.stage, m.samples = stage, m.samples[:0]
	}
	m.samples = append(m.samples, rateSample{now, done})
	for len(m.samples) > 2 && now.Sub(m.samples[1].at) >= rateWindow {
		m.samples = m.samples[1:]
	}
	// Two seconds at least: a transfer's first second, while its
	// connections open, says little about the rest.
	first := m.samples[0]
	span := now.Sub(first.at).Seconds()
	if span < 2 || done < first.done {
		return 0
	}
	return float64(done-first.done) / span
}

// ── Drawing ─────────────────────────────────────────────────────────────────

// barCells is the width of a connection's bar.
const barCells = 20

// liveLines lays out a frame for a terminal of width columns and height
// rows. head is the step's own text, like
// "ds.encrypt_upload: ⇅ Encrypting locally, then uploading". With cursor
// moves (multi), head has a line of its own, the numbers the next, and
// then come the connections, as many as fit; without, it is one line,
// where the label gives way to the numbers.
func liveLines(head string, f liveFrame, now time.Time, width, height int, multi bool) []string {
	head = strings.TrimRight(head, " ")
	stats := liveStats(f)
	if !multi {
		limit := max(width-1, 1)
		head = cut(head, max(limit-visibleCols(stats)-2, min(limit, 12)))
		return []string{fit(head+"  "+stats, width)}
	}
	lines := []string{fit(head, width), fit("  "+stats, width)}
	if !f.transfer {
		return lines
	}

	// Only connections moving a part get a row, numbered as the transfer
	// numbers them: a free one, or one whose part is all moved, drops out
	// until it takes another part.
	var active []int
	for i, c := range f.snap.Connections {
		if !connDone(c) {
			active = append(active, i)
		}
	}
	room := max(1, height-3)
	shown := active
	if len(active) > room {
		shown = active[:room-1]
	}
	numWidth := len(fmt.Sprint(len(f.snap.Connections)))
	partWidth := len(fmt.Sprint(f.snap.Parts))
	for _, i := range shown {
		lines = append(lines, fit(connLine(i+1, numWidth, partWidth, f.snap.Parts, f.snap.Connections[i], now), width))
	}
	if len(shown) < len(active) {
		more := len(active) - len(shown)
		lines = append(lines, fit(fmt.Sprintf("  %s... and %d more connection%s%s", ansiDim, more, pluralS(more), ansiReset), width))
	}
	return lines
}

// connDone reports whether a connection has nothing in flight: it is free,
// or its part is all moved. A connection waiting to retry is not done.
func connDone(c sdk.ConnectionStatus) bool {
	if c.Waiting {
		return false
	}
	return c.Part == 0 || (c.Size > 0 && c.Moved >= c.Size)
}

// liveStats is a frame's numbers: the stage, bytes, rate, time left and
// connections.
func liveStats(f liveFrame) string {
	var b strings.Builder
	b.WriteString(f.stage)
	if f.total > 0 {
		fmt.Fprintf(&b, " %s%s/%s %.0f%%%s", ansiWhite, formatBytes(f.done), formatBytes(f.total),
			float64(f.done)/float64(f.total)*100, ansiReset)
	}
	if f.rate > 0 {
		fmt.Fprintf(&b, "  %s%s/s", ansiDim, formatBytes(int64(f.rate)))
		if left := f.total - f.done; left > 0 {
			fmt.Fprintf(&b, ", %s left", fmtRemaining(time.Duration(float64(left)/f.rate*float64(time.Second))))
		}
		b.WriteString(ansiReset)
	}
	if f.transfer {
		fmt.Fprintf(&b, "  %s%d connection%s", ansiDim, f.snap.Threads, pluralS(f.snap.Threads))
		if f.snap.MaxThreads > f.snap.Threads {
			fmt.Fprintf(&b, ", up to %d", f.snap.MaxThreads)
		}
		b.WriteString(ansiReset)
	}
	return b.String()
}

// connLine is one connection's line: its part, a bar of the part's
// progress, the bytes and the connection's rate.
func connLine(n, numWidth, partWidth, parts int, c sdk.ConnectionStatus, now time.Time) string {
	num := fmt.Sprintf("  %s%*d%s ", ansiDim, numWidth, n, ansiReset)
	if c.Part == 0 {
		return num + ansiDim + "free" + ansiReset
	}
	part := fmt.Sprintf("part %*d of %d", partWidth, c.Part, parts)
	if c.Waiting {
		return fmt.Sprintf("%s%s  %s  %sretrying, attempt %d of %d%s", num, part, bar(0, c.Size),
			ansiYellow, c.Attempt, sdk.TransferAttempts, ansiReset)
	}
	line := fmt.Sprintf("%s%s  %s  %s/%s", num, part, bar(c.Moved, c.Size), formatBytes(c.Moved), formatBytes(c.Size))
	if elapsed := now.Sub(c.Since); !c.Since.IsZero() && elapsed >= time.Second && c.Moved > 0 {
		line += fmt.Sprintf("  %s%s/s%s", ansiDim, formatBytes(int64(float64(c.Moved)/elapsed.Seconds())), ansiReset)
	}
	if c.Attempt > 1 {
		line += fmt.Sprintf("  %sattempt %d of %d%s", ansiYellow, c.Attempt, sdk.TransferAttempts, ansiReset)
	}
	return line
}

// bar draws done of total as barCells cells.
func bar(done, total int64) string {
	filled := 0
	if total > 0 {
		filled = int(min(max(done, 0), total) * barCells / total)
	}
	return ansiCyan + strings.Repeat("█", filled) + ansiReset + ansiDim + strings.Repeat("░", barCells-filled) + ansiReset
}

// fmtRemaining renders a time left in whole seconds or minutes.
func fmtRemaining(d time.Duration) string {
	d = d.Round(time.Second)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm %02ds", int(d.Minutes()), int(d.Seconds())%60)
	default:
		return fmt.Sprintf("%dh %02dm", int(d.Hours()), int(d.Minutes())%60)
	}
}

// fit cuts s to width-1 columns, so a line never wraps, which would throw
// off the redraw.
func fit(s string, width int) string { return cut(s, max(width-1, 1)) }

// cut shortens s to cols columns, ending it with "..." when there is room.
// ANSI escapes take no columns; every other rune takes one.
func cut(s string, cols int) string {
	if visibleCols(s) <= cols {
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
			return s[:i] + ansiReset + mark
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		i += size
		n++
	}
	return s
}

// visibleCols is how many columns s takes on a terminal.
func visibleCols(s string) int {
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

// terminalSize is stderr's size, or 80 by 24 when it cannot be read.
func terminalSize() (width, height int) {
	w, h, err := term.GetSize(int(os.Stderr.Fd()))
	if err != nil || w <= 0 || h <= 0 {
		return 80, 24
	}
	return w, h
}

// drawLive replaces the live view with lines.
func drawLive(lines []string) {
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

// withLiveCleared removes the live view, if shown, and runs write, which
// writes to stderr. The view stays off until the next redraw: a step that
// ends uses it to leave no view behind.
func withLiveCleared(write func()) {
	live.mu.Lock()
	defer live.mu.Unlock()
	if live.lines > 0 {
		var b strings.Builder
		eraseLive(&b)
		_, _ = io.WriteString(os.Stderr, b.String()) // as in drawLive
	}
	live.last = nil
	write()
}

// aboveLive runs write, which writes whole lines to stderr, above the live
// view: the view, if shown, is removed and put straight back below them,
// so log lines scroll above a view that stays at the bottom.
func aboveLive(write func()) {
	live.mu.Lock()
	defer live.mu.Unlock()
	shown := live.lines > 0
	var b strings.Builder
	eraseLive(&b)
	_, _ = io.WriteString(os.Stderr, b.String()) // as in drawLive
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
	case liveCursor:
		b.WriteString("\r")
		if live.lines > 1 {
			fmt.Fprintf(b, "\033[%dA", live.lines-1)
		}
		b.WriteString("\033[J")
	default:
		width, _ := terminalSize()
		b.WriteString("\r" + strings.Repeat(" ", max(width-1, 1)) + "\r")
	}
	live.lines = 0
}
