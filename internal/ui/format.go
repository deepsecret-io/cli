// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package ui

import (
	"fmt"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/deepsecret-io/cli/internal/console"
)

// Plural returns "s" when n != 1.
func Plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// PluralS is the "s" of a plural: "" when n is 1.
func PluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// FormatRemaining renders a time left in whole seconds or minutes.
func FormatRemaining(d time.Duration) string {
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

// Ago renders how long ago t was.
func Ago(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// Ellipsis shortens s to limit characters for a table column, through safe:
// what it shortens comes from the server.
func Ellipsis(s string, limit int) string {
	r := []rune(console.Safe(s))
	if len(r) <= limit {
		return string(r)
	}
	return string(r[:limit-3]) + "..."
}

// FormatBytes writes b in binary units, named as such (KiB, MiB, GiB), as
// the logs and the web app name them.
func FormatBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// Abbrev shortens a long value, like a public key, to its first head and
// last tail characters, through safe.
func Abbrev(s string, head, tail int) string {
	s = console.Safe(s)
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
//	secret: Encrypting...
//	secret: Encryption complete after 367ms
//	secret: Uploading...
//	secret: Still uploading... [10s elapsed]
//	secret: Upload complete after 19.8s [id=0724ba1f]
//
// then its result as aligned key-value lines, or for a failure an Error
// block (Diagnostic). Logs are apart from this (package logging): off
// unless asked for, and never needed to follow a command.

// ThreadCountLabel is a --threads value for a log field. 0 means the SDK
// adapts the count to the connection; say so, so the log does not read as
// parallelism turned off.
func ThreadCountLabel(v int) string {
	if v <= 0 {
		return "adaptive"
	}
	return fmt.Sprintf("%d", v)
}

// ShortID is the first 8 characters of an ID, as step lines, tables and
// errors show it. The result blocks and the logs carry the full ID.
func ShortID(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

// lowerFirst is s with its first letter in lower case.
func lowerFirst(s string) string {
	r, n := utf8.DecodeRuneInString(s)
	return string(unicode.ToLower(r)) + s[n:]
}
