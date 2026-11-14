// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"regexp"
	"testing"
	"time"

	"github.com/deepsecret-io/cli/internal/flags"
)

// A send under the name of a secret the sender has adds a revision to that
// secret. So two sends without a name get different names, also within one
// second, and each name is one the CLI and the protocol accept: here
// letters, digits and hyphens only.
func TestDefaultNameIsUniquePerSend(t *testing.T) {
	now := time.Date(2026, 11, 14, 10, 15, 0, 0, time.UTC)
	for kind, pattern := range map[string]*regexp.Regexp{
		"message": regexp.MustCompile(`^message-20261114-101500-[0-9a-f]{6}$`),
		"secret":  regexp.MustCompile(`^secret-20261114-101500-[0-9a-f]{6}$`),
	} {
		first, second := defaultName(kind, now), defaultName(kind, now)
		if first == second {
			t.Errorf("two %s sends in one second are both named %q", kind, first)
		}
		for _, name := range []string{first, second} {
			if !pattern.MatchString(name) {
				t.Errorf("default name %q does not match %s", name, pattern)
			}
			var accepted string
			if err := flags.NewName(&accepted).Set(name); err != nil {
				t.Errorf("default name %q is not a valid --name: %v", name, err)
			}
		}
	}
}

// The Files line of an archived send counts its regular files, and its
// entries when folders or links add to them.
func TestArchivedFiles(t *testing.T) {
	for _, tc := range []struct {
		files, entries int
		want           string
	}{
		{1880, 2208, "1880 in one archive (2208 entries with folders and links)"},
		{12, 12, "12 in one archive"},
		{0, 1, "1 entry in one archive"},
		{0, 5, "5 entries in one archive"},
	} {
		if got := archivedFiles(tc.files, tc.entries); got != tc.want {
			t.Errorf("archivedFiles(%d, %d) = %q, want %q", tc.files, tc.entries, got, tc.want)
		}
	}
}
