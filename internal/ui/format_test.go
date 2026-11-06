// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package ui

import (
	"strings"
	"testing"
	"time"
)

func TestAbbrevHandlesShortAndHostileValues(t *testing.T) {
	for in, want := range map[string]string{
		"short":                             "short",
		strings.Repeat("a", 40):             "aaaaaaaa...aaaa",
		"\x1b[2J" + strings.Repeat("b", 30): "?[2Jbbbb...bbbb",
	} {
		if got := Abbrev(in, 8, 4); got != want {
			t.Errorf("abbrev(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFmtRemaining(t *testing.T) {
	for d, want := range map[time.Duration]string{
		7 * time.Second:                "7s",
		90 * time.Second:               "1m 30s",
		2*time.Hour + 5*time.Minute:    "2h 05m",
		59*time.Second + time.Second/2: "1m 00s",
	} {
		if got := FormatRemaining(d); got != want {
			t.Errorf("%v: %q, want %q", d, got, want)
		}
	}
}

func TestAgo(t *testing.T) {
	now := time.Now()
	for d, want := range map[time.Duration]string{
		10 * time.Second: "just now",
		5 * time.Minute:  "5m ago",
		3 * time.Hour:    "3h ago",
		72 * time.Hour:   "3d ago",
	} {
		if got := Ago(now.Add(-d)); got != want {
			t.Errorf("%s: %q, want %q", d, got, want)
		}
	}
}

// Ellipsis cuts on a character and neutralizes what it keeps.
func TestEllipsis(t *testing.T) {
	if got := Ellipsis("ünïcödé\x1b-name-that-is-long", 10); got != "ünïcödé..." {
		t.Errorf("ellipsis = %q", got)
	}
}
