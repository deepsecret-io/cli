// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build !windows

package prompt

import "os"

// openTerminal opens /dev/tty, the controlling terminal. Closing it does
// not wait for a read left waiting: once Fd has made the descriptor
// blocking (hideInput), Close leaves close(2) to the read's return, and
// on one still polled it wakes the read at once.
func openTerminal() (*Terminal, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	return &Terminal{In: tty, Out: tty, close: tty.Close}, nil
}
