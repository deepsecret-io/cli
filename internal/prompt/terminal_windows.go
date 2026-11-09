// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build windows

package prompt

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// errNoConsole is why a process none of whose standard handles is a
// console gets no terminal.
var errNoConsole = errors.New("none of stdin, stdout and stderr is a console")

// openTerminal opens the console the process runs in, CONIN$ and CONOUT$,
// when stdin, stdout or stderr is on it. A console none of them is on is
// one nobody reads or types into, such as the hidden console of a CI
// runner or of mintty without ConPTY, where a prompt would wait forever.
func openTerminal() (*Terminal, error) {
	if !anyConsole(os.Stdin, os.Stdout, os.Stderr) {
		return nil, errNoConsole
	}
	in, err := openConsole("CONIN$")
	if err != nil {
		return nil, err
	}
	out, err := openConsole("CONOUT$")
	if err != nil {
		_ = in.Close()
		return nil, err
	}
	restore := enableEscapes(out)
	return &Terminal{In: in, Out: out, close: func() error {
		restore()
		// Close waits for a read in progress on Windows, and an
		// interrupted prompt leaves one waiting for a line that will not
		// come: CONIN$ closes when that read ends, or with the process.
		go func() { _ = in.Close() }()
		return out.Close()
	}}, nil
}

// anyConsole reports whether one of files is a console.
func anyConsole(files ...*os.File) bool {
	for _, f := range files {
		var mode uint32
		if f != nil && windows.GetConsoleMode(windows.Handle(f.Fd()), &mode) == nil {
			return true
		}
	}
	return false
}

// openConsole opens the console device name, CONIN$ or CONOUT$, with
// CreateFile itself: under a long working folder os.OpenFile turns the
// name into a \\?\ path, which names a file in that folder, not the
// console. The handle is not inherited by child processes.
func openConsole(name string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	return os.NewFile(uintptr(h), name), nil
}

// enableEscapes turns on ANSI escape handling on the console output out,
// as the console package does for stderr, so an escape that clears a
// recovery code from the screen clears it with stderr redirected too. It
// returns what puts the mode back.
func enableEscapes(out *os.File) func() {
	h := windows.Handle(out.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil || mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
		return func() {}
	}
	if err := windows.SetConsoleMode(h, mode|windows.ENABLE_PROCESSED_OUTPUT|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING); err != nil {
		return func() {} // before Windows 10: the escapes show as text
	}
	return func() { _ = windows.SetConsoleMode(h, mode) } // best effort, as hideTerminalInput's
}
