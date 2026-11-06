// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package console

import (
	"testing"

	"github.com/deepsecret-io/cli/internal/testutil"
)

// fit cuts at the terminal's width in columns: escapes take none, and a
// multibyte rune takes one.
func TestFit(t *testing.T) {
	if got := Fit("\033[36mabcdef\033[0m", 4); testutil.AnsiEscape.ReplaceAllString(got, "") != "abc" {
		t.Fatalf("%q", got)
	}
	if got := Fit("█████", 3); got != "██"+Reset {
		t.Fatalf("%q", got)
	}
	if got := Fit("short", 80); got != "short" {
		t.Fatalf("%q", got)
	}
	if got := Cut("\033[1mabcdefghij\033[0m", 7); testutil.AnsiEscape.ReplaceAllString(got, "") != "abcd..." {
		t.Fatalf("%q", got)
	}
}
