// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package ui

import (
	"fmt"
	"os"
	"strings"

	"github.com/deepsecret-io/cli/internal/console"
)

// ── Errors and warnings ────────────────────────────────────────────────────

// Severity is an Error or a Warning block.
type Severity int

// The severities of a block.
const (
	SevError Severity = iota
	sevWarning
)

// Diagnostic prints an error or a warning as Terraform does: the
// severity and a one-line summary, then the detail, indented, on the
// lines below:
//
//	Error: Secret not found
//
//	  No secret 0724ba1f is shared with you. Check the ID with
//	  'secret list'.
func Diagnostic(sev Severity, summary, detail string) {
	label, color := "Error:", console.BoldRed
	if sev == sevWarning {
		label, color = "Warning:", console.Bold+console.Yellow
	}
	var b strings.Builder
	b.WriteString("\n")
	fmt.Fprintf(&b, "%s%s%s %s%s%s\n", color, label, console.Reset, console.Bold, console.Safe(summary), console.Reset)
	if detail = strings.TrimSpace(detail); detail != "" {
		b.WriteString("\n")
		for _, line := range strings.Split(console.SafeLines(detail), "\n") {
			if strings.TrimSpace(line) == "" {
				b.WriteString("\n")
				continue
			}
			b.WriteString("  " + line + "\n")
		}
	}
	console.AboveLive(func() { fmt.Fprint(os.Stderr, b.String()) })
}

// Warning prints a Warning block.
func Warning(summary, detail string) { Diagnostic(sevWarning, summary, detail) }

// ── Simple Output Helpers ───────────────────────────────────────────────────

// Success, Dimmed and Header print text that can hold values
// from outside the CLI, so they print it through console.SafeLines. KeyValue
// takes values that may carry the CLI's own styles: callers pass outside
// values through console.Safe.

// Success prints a command's closing result as one green sentence,
// as Terraform prints "Apply complete!".
func Success(msg string) {
	fmt.Fprintf(os.Stderr, "%s%s%s%s\n", console.Bold, console.Green, console.SafeLines(msg), console.Reset)
}

// KeyValue prints one line: the key, dimmed, then its value.
func KeyValue(key, value string) {
	fmt.Fprintf(os.Stderr, "  %s%-15s%s %s\n", console.Dim, key, console.Reset, value)
}

// KeyValues prints a list under one key: the key on the first line,
// later lines aligned under the first value.
func KeyValues(key string, values []string) {
	for i, v := range values {
		if i > 0 {
			key = ""
		}
		KeyValue(key, v)
	}
}

// Header prints a section's title, underlined.
func Header(title string) {
	title = console.Safe(title)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "  %s%s%s\n", console.Bold, title, console.Reset)
	fmt.Fprintf(os.Stderr, "  %s%s%s\n", console.Dim, strings.Repeat("─", len(title)+2), console.Reset)
}

// Dimmed prints a dimmed, indented line.
func Dimmed(msg string) {
	fmt.Fprintf(os.Stderr, "  %s%s%s\n", console.Dim, console.SafeLines(msg), console.Reset)
}

// Subject prints a line of subject's, as RunPipeline does: the
// subject, then msg.
func Subject(subject, msg string) {
	console.AboveLive(func() {
		fmt.Fprintf(os.Stderr, "%s%s:%s %s\n", console.Bold, console.Safe(subject), console.Reset, console.SafeLines(msg))
	})
}
