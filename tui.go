// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"errors"
	"fmt"
	"io/fs"
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

// ── Output ─────────────────────────────────────────────────────────────────
//
// What a command reports to its user goes to stderr, as Terraform reports
// a resource:
//
//	secret: Encrypting and uploading...
//	secret: Still encrypting and uploading... [10s elapsed]
//	secret: Upload complete after 36s [id=0724ba1f]
//
// then its result as aligned key-value lines, or for a failure an Error
// block (printDiagnostic). Logs are apart from this (logging.go): off
// unless asked for, and never needed to follow a command.

// threadCountLabel is a --threads value for a log field. 0 means the SDK
// adapts the count to the connection; say so, so the log does not read as
// parallelism turned off.
func threadCountLabel(v int) string {
	if v <= 0 {
		return "adaptive"
	}
	return fmt.Sprintf("%d", v)
}

// shortID is the first 8 characters of an ID, as step lines, tables and
// errors show it. The result blocks and the logs carry the full ID.
func shortID(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

// step is one unit of a command's work. label says what it does while it
// runs ("Encrypting and uploading") and done what it did once it finished
// ("Upload complete"). Its action returns a detail for the done line, such
// as "id=0724ba1f", or "".
type step struct {
	label          string
	done           string
	action         func() (string, error)                        // simple step
	progressAction func(progress chan<- float64) (string, error) // progress-tracked step
	live           *liveProgress                                 // live progress (encrypt, upload, download)
}

// run runs the step's action.
func (s step) run() (string, error) {
	if s.progressAction == nil {
		return s.action()
	}
	ch := make(chan float64, 100)
	go func() {
		for range ch {
		}
	}()
	return s.progressAction(ch)
}

// stillEvery is how often a step that shows no live progress says it is
// still running; tests shorten it.
var stillEvery = 10 * time.Second

// runPipeline runs steps one after another, each reported on subject's
// lines: started, still running every stillEvery, and done, with how long
// it took. A step's live progress shows with --progress instead of the
// still lines. The first failure stops the pipeline and is returned, for
// main to print.
func runPipeline(subject string, steps []step) error {
	head := ansiBold + safe(subject) + ":" + ansiReset + " "
	for _, s := range steps {
		// A label can hold a name from outside the CLI: a file's, a
		// secret's.
		label, doneLabel := safe(s.label), safe(s.done)
		start := time.Now()
		aboveLive(func() { fmt.Fprintf(os.Stderr, "%s%s...\n", head, label) })

		type outcome struct {
			detail string
			err    error
		}
		done := make(chan outcome, 1)
		go func() {
			detail, err := s.run()
			done <- outcome{detail, err}
		}()

		liveHead := head + label + "..."
		progress := s.live != nil && showProgress
		ticker := time.NewTicker(200 * time.Millisecond)
		cancelled := false
		logged, said := start, start
		var out outcome
	wait:
		for {
			select {
			case now := <-ticker.C:
				switch {
				case cancelled:
				case !progress:
					if now.Sub(said) >= stillEvery {
						said = now
						aboveLive(func() {
							fmt.Fprintf(os.Stderr, "%sStill %s... [%s elapsed]\n", head, lowerFirst(label), now.Sub(start).Round(time.Second))
						})
					}
				case stderrIsTerminal:
					// Progress redraws in place on a terminal.
					f := s.live.frame(now)
					width, height := terminalSize()
					drawLive(liveLines(liveHead, f, now, width, height, liveCursor))
				case now.Sub(logged) >= progressLogEvery:
					// Redirected, redraws would fill the output with partial
					// lines, so it is a line every progressLogEvery instead.
					logged = now
					f := s.live.frame(now)
					withLiveCleared(func() {
						fmt.Fprintf(os.Stderr, "%s  %s\n", liveHead, liveStats(f))
					})
				}
			case <-rootCtx.Done():
				// Ctrl+C or SIGTERM. The SDK's requests see the cancellation
				// and unwind within moments; say so at once, so the output
				// does not look frozen meanwhile.
				if !cancelled {
					cancelled = true
					aboveLive(func() {
						fmt.Fprintf(os.Stderr, "%sInterrupt received. Stopping, please wait...%s\n", ansiYellow, ansiReset)
					})
				}
			case out = <-done:
				break wait
			}
		}
		ticker.Stop()
		withLiveCleared(func() {})

		if out.err != nil {
			return out.err
		}
		line := head + doneLabel + " after " + stepDuration(time.Since(start))
		if out.detail != "" {
			line += " [" + safe(out.detail) + "]"
		}
		aboveLive(func() { fmt.Fprintln(os.Stderr, line) })
	}
	return nil
}

// progressLogEvery is how often --progress prints a line when stderr is
// not a terminal; tests shorten it.
var progressLogEvery = 5 * time.Second

// lowerFirst is s with its first letter in lower case.
func lowerFirst(s string) string {
	r, n := utf8.DecodeRuneInString(s)
	return string(unicode.ToLower(r)) + s[n:]
}

// upperFirst is s with its first letter in upper case.
func upperFirst(s string) string {
	r, n := utf8.DecodeRuneInString(s)
	return string(unicode.ToUpper(r)) + s[n:]
}

// stepDuration is how long a step took: milliseconds under a second,
// tenths of a second under a minute, then minutes and seconds.
func stepDuration(d time.Duration) string {
	switch {
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return d.Round(time.Second).String()
}

// ── Errors and warnings ────────────────────────────────────────────────────

// severity is an Error or a Warning block.
type severity int

const (
	sevError severity = iota
	sevWarning
)

// printDiagnostic prints an error or a warning as Terraform does: the
// severity and a one-line summary, then the detail, indented, on the
// lines below:
//
//	Error: Secret not found
//
//	  No secret 0724ba1f is shared with you. Check the ID with
//	  'secret list'.
func printDiagnostic(sev severity, summary, detail string) {
	label, color := "Error:", ansiBoldRed
	if sev == sevWarning {
		label, color = "Warning:", ansiBold+ansiYellow
	}
	var b strings.Builder
	b.WriteString("\n")
	fmt.Fprintf(&b, "%s%s%s %s%s%s\n", color, label, ansiReset, ansiBold, safe(summary), ansiReset)
	if detail = strings.TrimSpace(detail); detail != "" {
		b.WriteString("\n")
		for _, line := range strings.Split(safeLines(detail), "\n") {
			if strings.TrimSpace(line) == "" {
				b.WriteString("\n")
				continue
			}
			b.WriteString("  " + line + "\n")
		}
	}
	aboveLive(func() { fmt.Fprint(os.Stderr, b.String()) })
}

// printWarning prints a Warning block.
func printWarning(summary, detail string) { printDiagnostic(sevWarning, summary, detail) }

// detailedError is an error with the detail its Error block shows under
// the summary: what it means, and what to check or do next.
type detailedError struct {
	err    error
	detail string
}

func (e *detailedError) Error() string { return e.err.Error() }
func (e *detailedError) Unwrap() error { return e.err }

// withDetail gives err a detail for its Error block.
func withDetail(err error, detail string) error {
	if err == nil {
		return nil
	}
	return &detailedError{err: err, detail: detail}
}

// joinDetail is detail followed by the detail err carries (withDetail),
// such as how to finish an interrupted transfer, for an Error block that
// replaces err's own message.
func joinDetail(detail string, err error) string {
	var d *detailedError
	if !errors.As(err, &d) || d.detail == "" {
		return detail
	}
	if detail == "" {
		return d.detail
	}
	return detail + "\n\n" + d.detail
}

// describeError is err as an Error block: the first line of its message,
// starting with a capital, as the summary; the rest of the message and the
// detail it carries (withDetail) as the detail.
func describeError(err error) (summary, detail string) {
	first, rest, _ := strings.Cut(strings.TrimSpace(err.Error()), "\n")
	var parts []string
	if rest != "" {
		lines := strings.Split(rest, "\n")
		for i, l := range lines {
			lines[i] = strings.TrimPrefix(l, "  ")
		}
		parts = append(parts, strings.Join(lines, "\n"))
	}
	var d *detailedError
	if errors.As(err, &d) && d.detail != "" {
		parts = append(parts, d.detail)
	}
	if kc := keyChangedDetail(err); kc != "" {
		parts = append(parts, kc)
	}
	return upperFirst(first), strings.Join(parts, "\n\n")
}

// pathCause is what went wrong in a file operation, without the operation
// and the path that *fs.PathError and *os.LinkError put before it, for an
// error that names the file itself.
func pathCause(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	var le *os.LinkError
	if errors.As(err, &le) {
		return le.Err
	}
	return err
}

// ── Simple Output Helpers ───────────────────────────────────────────────────

// printSuccess, printDim and printHeader print text that can hold values
// from outside the CLI, so they print it through safeLines. printKeyValue
// takes values that may carry the CLI's own styles: callers pass outside
// values through safe.

// printSuccess prints a command's closing result as one green sentence,
// as Terraform prints "Apply complete!".
func printSuccess(msg string) {
	fmt.Fprintf(os.Stderr, "%s%s%s%s\n", ansiBold, ansiGreen, safeLines(msg), ansiReset)
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

// printSubject prints a line of subject's, as runPipeline does: the
// subject, then msg.
func printSubject(subject, msg string) {
	aboveLive(func() {
		fmt.Fprintf(os.Stderr, "%s%s:%s %s\n", ansiBold, safe(subject), ansiReset, safeLines(msg))
	})
}
