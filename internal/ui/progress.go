// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package ui

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/deepsecret-io/sdk"

	"github.com/deepsecret-io/cli/internal/console"
)

// ── Live progress ───────────────────────────────────────────────────────────
//
// While a step encrypts, uploads or downloads, a live view on stderr shows
// how far it is: a head line with the stage, bytes, rate and time left,
// and under it one bar per connection of the transfer, with the part it
// moves. It is redrawn in place a few times a second, only on a terminal.
// A terminal that cannot move the cursor gets the head line alone.

// LiveProgress is what a step reports for its live view.
type LiveProgress struct {
	// verb names the transfer, like "uploading"; empty for a step
	// without one.
	verb string
	// transfer is passed to the SDK, which fills it in.
	Transfer sdk.TransferStatus
	// pre is the step's stage when it has no transfer: encrypting a
	// send, reading a local file.
	Pre StageCounter

	rate rateMeter
}

// NewUploadProgress follows an upload of ciphertext already sealed.
func NewUploadProgress() *LiveProgress { return &LiveProgress{verb: "uploading"} }

// NewDownloadProgress follows a download.
func NewDownloadProgress() *LiveProgress { return &LiveProgress{verb: "downloading"} }

// NewStageProgress follows a step without a transfer, like encrypting
// to a local file. Its stage can change label.
func NewStageProgress(label string) *LiveProgress {
	return &LiveProgress{Pre: StageCounter{label: label}}
}

// StageCounter is a stage's progress, as the SDK reports it. Its label
// can change, as decryption goes from pass to pass.
type StageCounter struct {
	mu          sync.Mutex
	label       string
	done, total int64
}

// Set updates how far the stage is.
func (c *StageCounter) Set(done, total int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.done, c.total = done, total
}

// SetStage names a new stage and how far it is.
func (c *StageCounter) SetStage(label string, done, total int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.label, c.done, c.total = label, done, total
}

func (c *StageCounter) read() (label string, done, total int64) {
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
func (p *LiveProgress) frame(now time.Time) liveFrame {
	f := liveFrame{stage: "starting"}
	snap := p.Transfer.Snapshot()
	preLabel, preDone, preTotal := p.Pre.read()
	switch {
	case snap.Started && snap.PartsDone >= snap.Parts:
		f.stage, f.done, f.total = "finishing", snap.Done, snap.Total
	case snap.Started:
		f.stage, f.done, f.total, f.snap, f.transfer = p.verb, snap.Done, snap.Total, snap, true
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
// rows. head is the step's own line, like "secret: Uploading...". With cursor
// moves (multi), head has a line of its own, the numbers the next, and
// then come the connections, as many as fit; without, it is one line,
// where the label gives way to the numbers.
func liveLines(head string, f liveFrame, now time.Time, width, height int, multi bool) []string {
	head = strings.TrimRight(head, " ")
	stats := liveStats(f)
	if !multi {
		limit := max(width-1, 1)
		head = console.Cut(head, max(limit-console.VisibleCols(stats)-2, min(limit, 12)))
		return []string{console.Fit(head+"  "+stats, width)}
	}
	lines := []string{console.Fit(head, width), console.Fit("  "+stats, width)}
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
		lines = append(lines, console.Fit(connLine(i+1, numWidth, partWidth, f.snap.Parts, f.snap.Connections[i], now), width))
	}
	if len(shown) < len(active) {
		more := len(active) - len(shown)
		lines = append(lines, console.Fit(fmt.Sprintf("  %s... and %d more connection%s%s", console.Dim, more, PluralS(more), console.Reset), width))
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
		fmt.Fprintf(&b, " %s%s/%s %.0f%%%s", console.White, FormatBytes(f.done), FormatBytes(f.total),
			float64(f.done)/float64(f.total)*100, console.Reset)
	}
	if f.rate > 0 {
		fmt.Fprintf(&b, "  %s%s/s", console.Dim, FormatBytes(int64(f.rate)))
		if left := f.total - f.done; left > 0 {
			fmt.Fprintf(&b, ", %s left", FormatRemaining(time.Duration(float64(left)/f.rate*float64(time.Second))))
		}
		b.WriteString(console.Reset)
	}
	if f.transfer {
		fmt.Fprintf(&b, "  %s%d connection%s", console.Dim, f.snap.Threads, PluralS(f.snap.Threads))
		if f.snap.MaxThreads > f.snap.Threads {
			fmt.Fprintf(&b, ", up to %d", f.snap.MaxThreads)
		}
		b.WriteString(console.Reset)
	}
	return b.String()
}

// connLine is one connection's line: its part, a bar of the part's
// progress, the bytes and the connection's rate.
func connLine(n, numWidth, partWidth, parts int, c sdk.ConnectionStatus, now time.Time) string {
	num := fmt.Sprintf("  %s%*d%s ", console.Dim, numWidth, n, console.Reset)
	if c.Part == 0 {
		return num + console.Dim + "free" + console.Reset
	}
	part := fmt.Sprintf("part %*d of %d", partWidth, c.Part, parts)
	if c.Waiting {
		return fmt.Sprintf("%s%s  %s  %sretrying, attempt %d of %d%s", num, part, bar(0, c.Size),
			console.Yellow, c.Attempt, sdk.TransferAttempts, console.Reset)
	}
	line := fmt.Sprintf("%s%s  %s  %s/%s", num, part, bar(c.Moved, c.Size), FormatBytes(c.Moved), FormatBytes(c.Size))
	if elapsed := now.Sub(c.Since); !c.Since.IsZero() && elapsed >= time.Second && c.Moved > 0 {
		line += fmt.Sprintf("  %s%s/s%s", console.Dim, FormatBytes(int64(float64(c.Moved)/elapsed.Seconds())), console.Reset)
	}
	if c.Attempt > 1 {
		line += fmt.Sprintf("  %sattempt %d of %d%s", console.Yellow, c.Attempt, sdk.TransferAttempts, console.Reset)
	}
	return line
}

// bar draws done of total as barCells cells.
func bar(done, total int64) string {
	filled := 0
	if total > 0 {
		filled = int(min(max(done, 0), total) * barCells / total)
	}
	return console.Cyan + strings.Repeat("█", filled) + console.Reset + console.Dim + strings.Repeat("░", barCells-filled) + console.Reset
}
