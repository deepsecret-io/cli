// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build !windows

package prompt

import (
	"os"

	"golang.org/x/sys/unix"
)

// hideTerminalInput turns echo off on the terminal f, as term.ReadPassword
// does, and keeps canonical input and signals: the terminal edits the
// line, and Ctrl+C is a SIGINT. The change is made before it returns, so
// restore always undoes it.
func hideTerminalInput(f *os.File) (func(), error) {
	fd := int(f.Fd())
	old, err := unix.IoctlGetTermios(fd, ioctlGetTermios)
	if err != nil {
		return nil, err
	}
	hidden := *old
	hidden.Lflag &^= unix.ECHO
	hidden.Lflag |= unix.ICANON | unix.ISIG
	hidden.Iflag |= unix.ICRNL
	if err := unix.IoctlSetTermios(fd, ioctlSetTermios, &hidden); err != nil {
		return nil, err
	}
	return func() { _ = unix.IoctlSetTermios(fd, ioctlSetTermios, old) }, nil // best effort, as term.ReadPassword's
}
