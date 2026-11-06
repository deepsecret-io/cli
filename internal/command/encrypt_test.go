// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"testing"
)

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
