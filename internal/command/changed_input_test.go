// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"strings"
	"testing"
)

// A send stopped by a file that changed while it was read, such as a log
// being written, says how to send a copy: into a new folder only the user
// can read, since the copy is not encrypted, removed after the send.
func TestChangedInputDetail(t *testing.T) {
	for _, tc := range []struct {
		inputs []string
		want   []string
	}{
		{[]string{"/var/log"}, []string{
			`d=$(mktemp -d) && cp -a -- /var/log "$d"/ && secret encrypt "$d"/log`,
			`rm -rf "${d:?}"`,
		}},
		// A trailing slash would copy the folder's contents, not the folder.
		{[]string{"/srv/my logs/"}, []string{
			`cp -a -- '/srv/my logs' "$d"/ && secret encrypt "$d"/'my logs'`,
		}},
		{[]string{"a.log", "b.log"}, []string{
			`cp -a -- a.log b.log "$d"/ && secret encrypt "$d"/a.log "$d"/b.log`,
		}},
		// zsh expands a word that starts with "=".
		{[]string{"=x"}, []string{`cp -a -- '=x' "$d"/`}},
	} {
		got := changedInputDetail(tc.inputs, "linux")
		for _, want := range tc.want {
			if !strings.Contains(got, want) {
				t.Errorf("%v: the detail lacks %q:\n%s", tc.inputs, want, got)
			}
		}
	}

	// Windows has none of these commands: the detail says what to do.
	if got := changedInputDetail([]string{`C:\logs`}, "windows"); strings.Contains(got, "mktemp") || !strings.Contains(got, "copy") {
		t.Errorf("windows: %s", got)
	}
}
