// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build !windows

package console

// enableTerminalEscapes reports whether the terminal takes ANSI escapes,
// for colors and cursor moves. Unix terminals do.
func enableTerminalEscapes() bool { return true }

// StdinEOFKeys is how to end typed input at a terminal.
const StdinEOFKeys = "Ctrl+D"
