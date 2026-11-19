// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package fingerprint checks, matches and groups key fingerprints, as the user
// gives them and as the server stores them.
package fingerprint

import (
	"errors"
	"regexp"
	"strings"

	"github.com/deepsecret-io/cli/internal/console"
)

// fingerprintPattern is a key fingerprint or a prefix of one: hex, at
// least 16 characters so a prefix cannot match the wrong key.
var fingerprintPattern = regexp.MustCompile(`^[0-9a-f]{16,64}$`)

// Check checks a fingerprint or prefix and returns it in lower
// case. It is also a file name in the keystore, so nothing else passes.
func Check(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if !fingerprintPattern.MatchString(s) {
		return "", errors.New("must be a key fingerprint or a prefix of one: 16 to 64 hex characters")
	}
	return s, nil
}

// ── Fingerprint comparison ───────────────────────────────────────────────────

// Equal reports whether two full fingerprints name the same key. The
// server lists whole fingerprints, so a key on this device matches one
// exactly; only a prefix the user types is matched as a prefix.
func Equal(a, b string) bool {
	return strings.EqualFold(a, b)
}

// Group splits a fingerprint into two lines of eight groups of
// four, for reading it aloud and comparing it.
func Group(fp string) []string {
	var groups []string
	for i := 0; i < len(fp); i += 4 {
		groups = append(groups, console.Safe(fp[i:min(i+4, len(fp))]))
	}
	half := (len(groups) + 1) / 2
	return []string{strings.Join(groups[:half], " "), strings.Join(groups[half:], " ")}
}
