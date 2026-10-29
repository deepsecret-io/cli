// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"fmt"
	"os"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/term"
)

// ── ANSI colors (no external deps) ─────────────────────────────────────────

// Styles for stderr, where all colored output goes. They are empty when
// color is off: NO_COLOR is set (https://no-color.org), TERM is "dumb",
// stderr is not a terminal (redirected to a file or a pipe), or the
// Windows console cannot show them.
var (
	ansiReset   = "\033[0m"
	ansiBold    = "\033[1m"
	ansiDim     = "\033[2m"
	ansiRed     = "\033[31m"
	ansiGreen   = "\033[32m"
	ansiYellow  = "\033[33m"
	ansiCyan    = "\033[36m"
	ansiWhite   = "\033[37m"
	ansiBoldRed = "\033[1;31m"
)

// stderrIsTerminal says whether stderr is an interactive terminal. Live
// progress, which redraws in place, is only drawn there.
var stderrIsTerminal = term.IsTerminal(int(os.Stderr.Fd()))

// liveCursor says whether stderr takes ANSI escapes, so the live view can
// move the cursor to redraw several lines: a terminal, not TERM=dumb, and
// on Windows a console that turned them on.
var liveCursor bool

// stdoutIsTerminal says whether decrypted content printed to stdout lands
// on a terminal, where control characters in it would be acted on.
var stdoutIsTerminal = term.IsTerminal(int(os.Stdout.Fd()))

func init() {
	liveCursor = stderrIsTerminal && os.Getenv("TERM") != "dumb" && enableTerminalEscapes()
	if !liveCursor || os.Getenv("NO_COLOR") != "" {
		ansiReset, ansiBold, ansiDim, ansiRed, ansiGreen = "", "", "", "", ""
		ansiYellow, ansiCyan, ansiWhite, ansiBoldRed = "", "", "", ""
	}
}

// safe makes a value from outside the CLI (the server, a payload, another
// person) safe to print on one line: control characters, including the
// escape that starts terminal commands, invalid UTF-8 and invisible
// formatting marks such as a right-to-left override show as "?", so the
// value cannot send the terminal commands, move the cursor, recolor or
// rewrite earlier output, or reorder what is read.
func safe(s string) string { return sanitize(s, false) }

// safeLines is safe for text that may span lines: newlines and tabs stay.
func safeLines(s string) string { return sanitize(s, true) }

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

// abbrev shortens a long value, like a public key, to its first head and
// last tail characters, through safe.
func abbrev(s string, head, tail int) string {
	s = safe(s)
	if len(s) <= head+tail+3 {
		return s
	}
	return s[:head] + "..." + s[len(s)-tail:]
}

// ── Structured logging ─────────────────────────────────────────────────────
//
// Terraform-style level + context + message:
//
//	DEBUG  encrypt.upload: multipart parts=2 part_size=8 MiB
//	INFO   encrypt: → sending to self (alaa@example.com)
//	WARN   storage: presign URL expires in 30s
//	ERROR  decrypt: AEAD verification failed
//
// One line per event. No timestamps in interactive mode (terraform-style).
// DEBUG is hidden unless --debug. WARN/ERROR/INFO are always shown.

type logLevel int

const (
	lvlError logLevel = iota
	lvlWarn
	lvlInfo
	lvlDebug
)

func logLine(level logLevel, ctx, format string, args ...any) {
	if level == lvlDebug && !debug {
		return
	}
	msg := safeLines(fmt.Sprintf(format, args...))
	var tag, color string
	switch level {
	case lvlError:
		tag, color = "ERROR", ansiBoldRed
	case lvlWarn:
		tag, color = "WARN ", ansiYellow
	case lvlInfo:
		tag, color = "INFO ", ansiCyan
	case lvlDebug:
		tag, color = "DEBUG", ansiDim
	}
	// For DEBUG keep the entire line dim. For others, color only the tag
	// so the message text stays legible. A live view moves below the line.
	withLiveCleared(func() {
		if level == lvlDebug {
			fmt.Fprintf(os.Stderr, "%s%s  %s: %s%s\n", color, tag, ctx, msg, ansiReset)
		} else {
			fmt.Fprintf(os.Stderr, "%s%s%s  %s: %s\n", color, tag, ansiReset, ctx, msg)
		}
	})
}

func logDebug(ctx, format string, args ...any)  { logLine(lvlDebug, ctx, format, args...) }
func logInfof(ctx, format string, args ...any)  { logLine(lvlInfo, ctx, format, args...) }
func logWarnf(ctx, format string, args ...any)  { logLine(lvlWarn, ctx, format, args...) }
func logErrorf(ctx, format string, args ...any) { logLine(lvlError, ctx, format, args...) }

// dbg / dbgErr: kept as thin wrappers for any remaining call sites.
// New code should use logDebug / logError directly.
func dbg(context string, format string, args ...any) { logDebug(context, format, args...) }
func dbgErr(context string, err error) {
	if err == nil {
		return
	}
	logErrorf(context, "%v", err)
}

// threadCountLabel renders a thread-count flag value for debug logs. 0
// means the SDK adapts the count to the connection; say so, so the log
// doesn't look like the user disabled parallelism.
func threadCountLabel(v int) string {
	if v <= 0 {
		return "adaptive"
	}
	return fmt.Sprintf("%d", v)
}

// shortID truncates a UUID/hash to the first 8 chars for log readability.
// Full values are still available with `--debug` and grep on the secret_id
// in the summary block.
func shortID(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

// ── Logging ────────────────────────────────────────────────────────────────

// step represents a single unit of work in a pipeline.
type step struct {
	label          string
	action         func() (string, error)                        // simple step
	progressAction func(progress chan<- float64) (string, error) // progress-tracked step
	live           *liveProgress                                 // live progress (encrypt, upload, download)
}

type keyValue struct {
	key   string
	value string
}

// toPrefix converts a title like "Encrypt Secret" to "ds.encrypt_secret"
func toPrefix(title string) string {
	s := strings.ToLower(title)
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, "&", "_")
	s = strings.ReplaceAll(s, "(", "")
	s = strings.ReplaceAll(s, ")", "")
	for strings.Contains(s, "__") {
		s = strings.ReplaceAll(s, "__", "_")
	}
	s = strings.TrimRight(s, "_")
	return "ds." + s
}

// runPipeline executes steps sequentially, printing each as a log line.
func runPipeline(title string, steps []step, summary []keyValue) error {
	prefix := toPrefix(title)

	// Compute max label width for alignment
	maxLabel := 0
	for _, s := range steps {
		if len(s.label) > maxLabel {
			maxLabel = len(s.label)
		}
	}

	for _, s := range steps {
		start := time.Now()

		var detail string
		var err error

		if s.live != nil {
			// Run action in background, redraw its live progress
			done := make(chan struct{})
			var actionDetail string
			var actionErr error

			go func() {
				if s.progressAction != nil {
					ch := make(chan float64, 100)
					go func() {
						for range ch {
						}
					}()
					actionDetail, actionErr = s.progressAction(ch)
				} else {
					actionDetail, actionErr = s.action()
				}
				close(done)
			}()

			head := liveHead(prefix, s.label, maxLabel)
			ticker := time.NewTicker(200 * time.Millisecond)
			cancelled := false
			logged := time.Now()
		transferLoop:
			for {
				select {
				case now := <-ticker.C:
					// Progress shows only with --progress, so the output
					// stays plain for pipes, scripts and logs. On a terminal
					// it redraws in place; redirected, redraws would fill
					// the output with partial lines, so it is a line every
					// progressLogEvery instead.
					if !showProgress || cancelled {
						continue
					}
					f := s.live.frame(now)
					switch {
					case stderrIsTerminal:
						width, height := terminalSize()
						drawLive(liveLines(head, f, now, width, height, liveCursor))
					case now.Sub(logged) >= progressLogEvery:
						logged = now
						withLiveCleared(func() {
							fmt.Fprintf(os.Stderr, "%s  %s\n", strings.TrimRight(head, " "), liveStats(f))
						})
					}
				case <-rootCtx.Done():
					// Ctrl+C arrived. The SDK's retry loops also see the
					// cancellation and unwind in a few ms, but show the user
					// immediate feedback so the live view doesn't look
					// frozen while the goroutine drains.
					if !cancelled {
						cancelled = true
						withLiveCleared(func() {
							fmt.Fprintf(os.Stderr, "  %s⏳%s cancelling, please wait...\n", ansiYellow, ansiReset)
						})
					}
				case <-done:
					break transferLoop
				}
			}
			ticker.Stop()
			withLiveCleared(func() {})

			detail = actionDetail
			err = actionErr
		} else if s.progressAction != nil {
			ch := make(chan float64, 100)
			go func() {
				for range ch {
				}
			}()
			detail, err = s.progressAction(ch)
		} else {
			detail, err = s.action()
		}

		elapsed := time.Since(start)

		if err != nil {
			logStepError(prefix, s.label, maxLabel, err, elapsed)
			return &displayedError{err: err}
		}

		logStep(prefix, s.label, maxLabel, detail, elapsed)
	}

	// Print summary
	if len(summary) > 0 && debug {
		fmt.Fprintln(os.Stderr)
		maxKeyLen := 0
		for _, kv := range summary {
			if len(kv.key) > maxKeyLen {
				maxKeyLen = len(kv.key)
			}
		}
		for _, kv := range summary {
			fmt.Fprintf(os.Stderr, "  %s%-*s%s  %s\n", ansiDim, maxKeyLen, kv.key, ansiReset, kv.value)
		}
		fmt.Fprintln(os.Stderr)
	}

	return nil
}

// progressLogEvery is how often --progress prints a line when stderr is
// not a terminal; tests shorten it.
var progressLogEvery = 5 * time.Second

// liveHead is the start of a step's live view: its prefix and label,
// padded to width.
func liveHead(prefix, label string, width int) string {
	return fmt.Sprintf("%s%s:%s %s⇅%s %-*s", ansiCyan, prefix, ansiReset, ansiYellow, ansiReset, width, safe(label))
}

// displayedError wraps an error that has already been printed to stderr.
// main() checks for this to avoid double-printing.
type displayedError struct{ err error }

func (e *displayedError) Error() string { return e.err.Error() }
func (e *displayedError) Unwrap() error { return e.err }

// logStep prints a single aligned log line.
// Always shows label + checkmark + duration. Detail only in debug mode.
func logStep(prefix, label string, padWidth int, detail string, d time.Duration) {
	detailStr := ""
	if debug && detail != "" {
		detailStr = ansiDim + " " + safe(detail) + ansiReset
	}
	fmt.Fprintf(os.Stderr, "%s%s:%s %s✓%s %-*s%s  %s%s%s\n",
		ansiCyan, prefix, ansiReset,
		ansiGreen, ansiReset,
		padWidth, label,
		detailStr,
		ansiDim, fmtDuration(d), ansiReset,
	)
}

// logStepError prints a failed step log line.
func logStepError(prefix, label string, padWidth int, err error, d time.Duration) {
	fmt.Fprintf(os.Stderr, "%s%s:%s %s✗%s %-*s  %s%s%s  %s%s%s\n",
		ansiCyan, prefix, ansiReset,
		ansiBoldRed, ansiReset,
		padWidth, safe(label),
		ansiRed, safeLines(err.Error()), ansiReset,
		ansiDim, fmtDuration(d), ansiReset,
	)
}

// logInfo prints a general info line with prefix.
func logInfo(prefix, msg string) {
	if !debug {
		return
	}
	fmt.Fprintf(os.Stderr, "%s%s:%s %s\n", ansiCyan, prefix, ansiReset, msg)
}

// ── Simple Output Helpers ───────────────────────────────────────────────────

// printSuccess, printError, printDim and printHeader print text that can
// hold values from outside the CLI, so they print it through safeLines.
// printKeyValue takes values that may carry the CLI's own styles: callers
// pass outside values through safe.

func printSuccess(msg string) {
	fmt.Fprintf(os.Stderr, "  %s✓%s %s\n", ansiGreen, ansiReset, safeLines(msg))
}

func printError(msg string) {
	fmt.Fprintf(os.Stderr, "  %s✗%s %s\n", ansiRed, ansiReset, safeLines(msg))
}

func printKeyValue(key, value string) {
	fmt.Fprintf(os.Stderr, "  %s%-14s%s %s\n", ansiDim, key, ansiReset, value)
}

// printKeyValues prints a list under one key: the key on the first line,
// later lines aligned under the first value.
func printKeyValues(key string, values []string) {
	for i, v := range values {
		if i > 0 {
			key = ""
		}
		printKeyValue(key, v)
	}
}

func printHeader(title string) {
	title = safe(title)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "  %s%s%s\n", ansiBold, title, ansiReset)
	fmt.Fprintf(os.Stderr, "  %s%s%s\n", ansiDim, strings.Repeat("─", len(title)+2), ansiReset)
}

func printDim(msg string) {
	fmt.Fprintf(os.Stderr, "  %s%s%s\n", ansiDim, safeLines(msg), ansiReset)
}

// ── Timer helper ────────────────────────────────────────────────────────────

func fmtDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}
