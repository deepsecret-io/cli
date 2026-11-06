// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build windows

package console

import (
	"os"

	"golang.org/x/sys/windows"
)

// enableTerminalEscapes turns on ANSI escape handling for the stderr
// console (Windows 10 and later), and reports whether it is on. Older
// consoles print escapes as text, so color and cursor moves stay off
// there.
func enableTerminalEscapes() bool {
	h := windows.Handle(os.Stderr.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return false
	}
	if mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
		return true
	}
	return windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) == nil
}

// StdinEOFKeys is how to end typed input at a terminal.
const StdinEOFKeys = "Ctrl+Z, then Enter"
