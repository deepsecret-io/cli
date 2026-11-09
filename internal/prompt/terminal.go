// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package prompt

import "os"

// Terminal is where the user reads a prompt and types the answer, apart
// from stdin and stdout, so a prompt still works while they carry data:
// /dev/tty on Unix, the console (CONIN$ and CONOUT$) on Windows.
type Terminal struct {
	In, Out *os.File
	close   func() error
}

// OpenTerminal opens the terminal of the process, or fails when it has
// none a user can type into, as under automation.
func OpenTerminal() (*Terminal, error) { return openTerminal() }

// Close closes the terminal. It does not wait for a read left waiting on
// it (readHidden, readVisibleLine), which ends with the process.
func (t *Terminal) Close() error { return t.close() }
