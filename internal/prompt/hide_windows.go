// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build windows

package prompt

import (
	"os"

	"golang.org/x/sys/windows"
)

// hideTerminalInput turns echo off on the console f and keeps its line
// input and Ctrl+C: the console edits the line, and Ctrl+C is an
// interrupt. The change is made before it returns, so restore always
// undoes it.
func hideTerminalInput(f *os.File) (func(), error) {
	h := windows.Handle(f.Fd())
	var old uint32
	if err := windows.GetConsoleMode(h, &old); err != nil {
		return nil, err
	}
	// Without VT input, keys like the arrows send nothing into the line.
	hidden := old&^(windows.ENABLE_ECHO_INPUT|windows.ENABLE_VIRTUAL_TERMINAL_INPUT) | windows.ENABLE_LINE_INPUT | windows.ENABLE_PROCESSED_INPUT
	if err := windows.SetConsoleMode(h, hidden); err != nil {
		return nil, err
	}
	return func() { _ = windows.SetConsoleMode(h, old) }, nil // best effort, as term.ReadPassword's
}
