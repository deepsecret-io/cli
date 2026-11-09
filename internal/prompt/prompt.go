// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package prompt reads from the terminal: passwords, PINs and recovery codes
// without echo, and plain lines.
package prompt

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"unicode/utf8"
)

// Password reads a password, a PIN or a recovery code from the terminal
// without echoing. It prefers the terminal (OpenTerminal) over stdin so
// the prompt still works when the caller is piping data into stdin (e.g.
// `kubectl ... | secret encrypt`), where stdin is a pipe and reading it as a
// terminal would fail with "inappropriate ioctl for device". Ctrl+C stops
// the command at once, as it does anywhere else. The underlying byte buffer
// is overwritten with zeros before returning; the only remaining copy is
// the immutable Go string the caller holds.
func Password(ctx context.Context, prompt string) (string, error) {
	// Fallback: stdin is the only thing left. This is the path where no
	// terminal opens (some CI containers, or Windows with none of stdin,
	// stdout and stderr on a console).
	in, out := os.Stdin, os.Stderr
	if t, err := OpenTerminal(); err == nil {
		// Closing it does not end or wait for a read left waiting
		// (readHidden).
		defer func() { _ = t.Close() }() // opened to read one line
		in, out = t.In, t.Out
	}
	OpenLine(out, prompt)
	pw, err := readHidden(ctx, in)
	EndLine()
	if err != nil {
		zeroBytes(pw)
		return "", fmt.Errorf("could not read the password: %w", err)
	}
	defer zeroBytes(pw)
	return strings.TrimSpace(string(pw)), nil
}

// promptMu guards promptOut, where a hidden prompt's line is open. The
// interrupt line ends it first (EndLine), so it never lands on the
// prompt's line, and still lines wait while it is open.
var (
	promptMu  sync.Mutex
	promptOut io.Writer
)

// OpenLine shows prompt on out and keeps its line open.
func OpenLine(out io.Writer, prompt string) {
	promptMu.Lock()
	defer promptMu.Unlock()
	_, _ = fmt.Fprint(out, prompt) // a prompt that cannot be shown still reads; a terminal that cannot be read fails after
	promptOut = out
}

// EndLine ends an open prompt's line, once, on the prompt's own
// output.
func EndLine() {
	promptMu.Lock()
	defer promptMu.Unlock()
	if promptOut != nil {
		_, _ = fmt.Fprintln(promptOut)
		promptOut = nil
	}
}

// LineOpen reports whether a hidden prompt's line is open.
func LineOpen() bool {
	promptMu.Lock()
	defer promptMu.Unlock()
	return promptOut != nil
}

// hideInput turns the terminal's echo off until restore is called, keeping
// its line editing and Ctrl+C; tests replace it.
var hideInput = hideTerminalInput

// maxHiddenLine is the longest line a hidden prompt takes, so its buffer
// never grows and leaves a copy behind.
const maxHiddenLine = 1024

// readHidden reads a line from the terminal in without echoing it. Ctrl+C
// keeps its meaning, a SIGINT for the command and the rest of a pipeline,
// and the signal (ctx) ends the read at once: the terminal is put
// back, and the read is left waiting for a line that will not come before
// the process exits.
func readHidden(ctx context.Context, in *os.File) ([]byte, error) {
	restore, err := hideInput(in)
	if err != nil {
		return nil, err
	}
	defer restore() // echo back, before the prompt's line ends

	type read struct {
		line []byte
		err  error
	}
	got := make(chan read, 1)
	go func() {
		line, err := readHiddenLine(in)
		got <- read{line, err}
	}()
	select {
	case r := <-got:
		return r.line, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// readHiddenLine reads a line the terminal hands over at Enter; the
// terminal does the editing. A backspace that reaches it still removes the
// last character, as on a console that sends it. A line over maxHiddenLine
// is read to its end and refused, so no part of it is left for the shell
// to read as a command.
func readHiddenLine(r io.Reader) ([]byte, error) {
	line := make([]byte, 0, maxHiddenLine)
	var key [1]byte
	defer func() { key[0] = 0 }()
	for {
		n, err := r.Read(key[:])
		if n == 0 {
			switch {
			case err == nil:
				continue
			case errors.Is(err, io.EOF) && len(line) > 0:
				return line, nil
			}
			return line, err
		}
		switch c := key[0]; c {
		case '\n':
			return line, nil
		case '\r': // before the '\n' of a Windows line
		case 0x7f, '\b':
			_, size := utf8.DecodeLastRune(line)
			zeroBytes(line[len(line)-size:])
			line = line[:len(line)-size]
		default:
			if len(line) == maxHiddenLine {
				for key[0] != '\n' {
					if n, err := r.Read(key[:]); n == 0 && err != nil {
						break
					}
				}
				return line, fmt.Errorf("the input is over %d bytes", maxHiddenLine)
			}
			line = append(line, c)
		}
	}
}

// zeroBytes overwrites b with zeros. Best-effort: a future Go version could
// theoretically optimise this away, but the compiler currently does not when
// the slice escapes (which it does, via pw being a function argument).
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// PasswordConfirm reads and confirms a new password.
func PasswordConfirm(ctx context.Context, prompt string) (string, error) {
	pw, err := Password(ctx, prompt)
	if err != nil {
		return "", err
	}
	if pw == "" {
		return "", nil
	}
	confirm, err := Password(ctx, "Confirm password: ")
	if err != nil {
		return "", err
	}
	if pw != confirm {
		return "", fmt.Errorf("passwords do not match")
	}
	return pw, nil
}

// Line reads a line the user types where it can be seen, from the
// terminal when there is one. As with a hidden prompt, the signal (ctx) ends
// it at once, while the read is left waiting for a line that will not come.
func Line(ctx context.Context, prompt string) (string, error) {
	var in io.Reader = os.Stdin
	out := os.Stderr
	if t, err := OpenTerminal(); err == nil {
		defer func() { _ = t.Close() }() // does not wait for a read left waiting
		in, out = t.In, t.Out
	}
	_, _ = fmt.Fprint(out, prompt)
	line, err := readVisibleLine(ctx, in)
	if errors.Is(err, context.Canceled) {
		_, _ = fmt.Fprintln(out) // nothing ended the prompt's line
	}
	return line, err
}

// maxVisibleLine is the most of a line a visible prompt keeps.
const maxVisibleLine = 256

// readVisibleLine reads a line from in, until ctx is done.
func readVisibleLine(ctx context.Context, in io.Reader) (string, error) {
	type read struct {
		line string
		err  error
	}
	got := make(chan read, 1)
	go func() {
		r := bufio.NewReaderSize(in, maxVisibleLine)
		line, err := r.ReadSlice('\n')
		text := string(line)
		for errors.Is(err, bufio.ErrBufferFull) {
			// The rest of a long line is read and dropped, or the shell
			// would run it after the command ends.
			_, err = r.ReadSlice('\n')
		}
		got <- read{text, err}
	}()
	select {
	case r := <-got:
		if r.err != nil && r.line == "" {
			return "", fmt.Errorf("could not read your answer: %w", r.err)
		}
		return strings.TrimSpace(r.line), nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}
