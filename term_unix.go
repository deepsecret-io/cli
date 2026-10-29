// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build !windows

package main

// enableTerminalEscapes reports whether the terminal takes ANSI escapes,
// for colors and cursor moves. Unix terminals do.
func enableTerminalEscapes() bool { return true }

// stdinEOFKeys is how to end typed input at a terminal.
const stdinEOFKeys = "Ctrl+D"
