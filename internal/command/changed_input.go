// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"path"
	"strings"
)

// changedInputDetail tells how to send inputs one of whose files changed
// while it was read, as a log does while it is written: copy them, send the
// copy, remove it. The copy is not encrypted, so it goes into a new folder
// only the user can read (mktemp -d makes it 0700), and the removal refuses
// an empty folder name. goos is runtime.GOOS: Windows has no such commands.
func changedInputDetail(inputs []string, goos string) string {
	const why = "A file changed while it was read, as a log does while it is written.\n"
	if goos == "windows" {
		return why + "Copy the files into a folder only you can read, send the copy with the same options,\nthen delete the copy: it is not encrypted."
	}
	// The commands are for a POSIX shell, so the inputs are POSIX paths:
	// path, not filepath, which would turn them into Windows paths when the
	// tests run there.
	srcs := make([]string, len(inputs))
	copies := make([]string, len(inputs))
	for i, in := range inputs {
		// A trailing slash would copy a folder's contents, not the folder.
		in = path.Clean(in)
		srcs[i] = shellWord(in)
		copies[i] = `"$d"/` + shellWord(path.Base(in))
	}
	return why +
		"Send a copy instead, with the same options. The copy is not encrypted: it goes into\n" +
		"a new folder only you can read, removed after the send.\n\n" +
		`  d=$(mktemp -d) && cp -a -- ` + strings.Join(srcs, " ") + ` "$d"/ && secret encrypt ` + strings.Join(copies, " ") + "\n" +
		`  rm -rf "${d:?}"`
}

// shellWord quotes s for a POSIX shell unless it holds only characters a
// shell leaves as they are. A leading "=" is quoted too: zsh expands it.
func shellWord(s string) string {
	const plain = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@%+=:,./_-"
	if s != "" && s[0] != '=' && strings.Trim(s, plain) == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
