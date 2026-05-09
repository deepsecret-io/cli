// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// ── ANSI colors (no external deps) ─────────────────────────────────────────

const (
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
	msg := fmt.Sprintf(format, args...)
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
	// so the message text stays legible.
	if level == lvlDebug {
		fmt.Fprintf(os.Stderr, "%s%s  %s: %s%s\n", color, tag, ctx, msg, ansiReset)
	} else {
		fmt.Fprintf(os.Stderr, "%s%s%s  %s: %s\n", color, tag, ansiReset, ctx, msg)
	}
}

func logDebug(ctx, format string, args ...any)  { logLine(lvlDebug, ctx, format, args...) }
func logInfof(ctx, format string, args ...any)  { logLine(lvlInfo, ctx, format, args...) }
func logWarnf(ctx, format string, args ...any)  { logLine(lvlWarn, ctx, format, args...) }
func logErrorf(ctx, format string, args ...any) { logLine(lvlError, ctx, format, args...) }

// dbg / dbgErr — kept as thin wrappers for any remaining call sites.
// New code should use logDebug / logError directly.
func dbg(context string, format string, args ...any) { logDebug(context, format, args...) }
func dbgErr(context string, err error) {
	if err == nil {
		return
	}
	logErrorf(context, "%v", err)
}

// threadCountLabel renders a thread-count flag value for debug logs.
// 0 means "use SDK default"; render that explicitly so the log doesn't
// look like the user disabled parallelism.
func threadCountLabel(v, sdkDefault int) string {
	if v <= 0 {
		return fmt.Sprintf("default(%d)", sdkDefault)
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
	transfer       *transferProgress                             // live transfer progress (upload/download)
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

		if s.transfer != nil {
			// Run action in background, poll transfer progress
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

			ticker := time.NewTicker(250 * time.Millisecond)
		transferLoop:
			for {
				select {
				case <-ticker.C:
					if s.transfer.total > 0 {
						pct := s.transfer.Pct() * 100
						speed := s.transfer.Speed()
						transferred := formatBytes(s.transfer.transferred.Load())
						total := formatBytes(s.transfer.total)
						fmt.Fprintf(os.Stderr, "\r%s%s:%s %s⇅%s %-*s  %s%s/%s %.0f%%%s  %s%s%s",
							ansiCyan, prefix, ansiReset,
							ansiYellow, ansiReset,
							maxLabel, s.label,
							ansiWhite, transferred, total, pct, ansiReset,
							ansiDim, speed, ansiReset)
					}
				case <-done:
					break transferLoop
				}
			}
			ticker.Stop()
			fmt.Fprintf(os.Stderr, "\r%s\r\n", strings.Repeat(" ", 140))

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
		detailStr = ansiDim + " " + detail + ansiReset
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
		padWidth, label,
		ansiRed, err.Error(), ansiReset,
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

func printSuccess(msg string) {
	fmt.Fprintf(os.Stderr, "  %s✓%s %s\n", ansiGreen, ansiReset, msg)
}

func printError(msg string) {
	fmt.Fprintf(os.Stderr, "  %s✗%s %s\n", ansiRed, ansiReset, msg)
}

func printKeyValue(key, value string) {
	fmt.Fprintf(os.Stderr, "  %s%-14s%s %s\n", ansiDim, key, ansiReset, value)
}

func printHeader(title string) {
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "  %s%s%s\n", ansiBold, title, ansiReset)
	fmt.Fprintf(os.Stderr, "  %s%s%s\n", ansiDim, strings.Repeat("─", len(title)+2), ansiReset)
}

func printDim(msg string) {
	fmt.Fprintf(os.Stderr, "  %s%s%s\n", ansiDim, msg, ansiReset)
}

// ── Timer helper ────────────────────────────────────────────────────────────

func fmtDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}

