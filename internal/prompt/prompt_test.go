// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package prompt

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// A hidden prompt's line ends at Enter, with a Windows line's '\r' left
// out; a backspace that reaches it removes a whole character; a line over
// maxHiddenLine is refused.
func TestReadHiddenLine(t *testing.T) {
	for _, c := range []struct {
		keys, want string
		fails      bool
	}{
		{"1234\n", "1234", false},
		{"1234\r\n", "1234", false},
		{"12x\x7f34\n", "1234", false},
		{"12x\b34\n", "1234", false},
		{"pä\x7f\n", "p", false},
		{"\x7f12\n", "12", false},
		{"12", "12", false}, // the input ends without Enter
		{"", "", true},      // Ctrl+D on an empty line
		{strings.Repeat("a", maxHiddenLine) + "\n", strings.Repeat("a", maxHiddenLine), false},
		{strings.Repeat("a", maxHiddenLine+1) + "\n", "", true},
	} {
		got, err := readHiddenLine(strings.NewReader(c.keys))
		if (err != nil) != c.fails || (!c.fails && string(got) != c.want) {
			t.Errorf("keys %q: %q, %v", c.keys, got, err)
		}
	}
}

// A hidden prompt reads its line with the terminal's echo off, and a
// signal that stops the command (ctx) ends it at once, while the read
// still waits; either way the terminal is put back.
func TestReadHidden(t *testing.T) {
	savedHide := hideInput
	t.Cleanup(func() { hideInput = savedHide })
	hidden, restored := 0, 0
	hideInput = func(*os.File) (func(), error) {
		hidden++
		return func() { restored++ }, nil
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close(); _ = r.Close() }) // ends the read left waiting

	go func() { _, _ = w.Write([]byte("1234\n")) }()
	if line, err := readHidden(context.Background(), r); err != nil || string(line) != "1234" || hidden != 1 || restored != 1 {
		t.Fatalf("answered: %q, %v (hidden %d, restored %d)", line, err, hidden, restored)
	}

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	start := time.Now()
	if _, err := readHidden(ctx, r); !errors.Is(err, context.Canceled) || restored != 2 {
		t.Fatalf("interrupted: %v (restored %d)", err, restored)
	}
	if waited := time.Since(start); waited > 2*time.Second {
		t.Fatalf("the interrupt took %v to end the prompt", waited)
	}

	hideInput = func(*os.File) (func(), error) { return nil, errors.New("not a terminal") }
	if _, err := readHidden(ctx, r); err == nil {
		t.Fatal("a file that is not a terminal was read")
	}
}

// An open prompt's line is ended once, on the prompt's own output, by
// whichever comes first: the answer or the interrupt line.
func TestPromptLine(t *testing.T) {
	var b bytes.Buffer
	OpenLine(&b, "PIN: ")
	if !LineOpen() {
		t.Fatal("the prompt's line is not open")
	}
	EndLine()
	EndLine()
	if b.String() != "PIN: \n" || LineOpen() {
		t.Fatalf("%q", b.String())
	}
}

// A line over maxHiddenLine is read to its end, so what follows it is the
// next line's, not the shell's.
func TestReadHiddenLineDrainsALongLine(t *testing.T) {
	r := strings.NewReader(strings.Repeat("a", maxHiddenLine+50) + "\nnext\n")
	if _, err := readHiddenLine(r); err == nil {
		t.Fatal("a line over the limit was taken")
	}
	if line, err := readHiddenLine(r); err != nil || string(line) != "next" {
		t.Fatalf("after the long line: %q, %v", line, err)
	}
}

// A visible prompt returns the line typed, and the signal that stops the
// command (ctx) ends it at once, while the read still waits.
func TestReadVisibleLine(t *testing.T) {
	if line, err := readVisibleLine(context.Background(), strings.NewReader("  group one \nmore")); err != nil || line != "group one" {
		t.Fatalf("answered: %q, %v", line, err)
	}
	if _, err := readVisibleLine(context.Background(), strings.NewReader("")); err == nil {
		t.Fatal("nothing to read gave no error")
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close(); _ = r.Close() }) // ends the read left waiting
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	done := make(chan error, 1)
	go func() {
		_, err := readVisibleLine(ctx, r)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("interrupted: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the signal did not end the prompt")
	}
}

// A line longer than a visible prompt keeps is read to its end, so the rest
// does not stay on the terminal for the shell to run.
func TestReadVisibleLineDrainsALongLine(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close(); _ = r.Close() })
	if _, err := w.Write([]byte(strings.Repeat("x", 3*maxVisibleLine) + "\n")); err != nil {
		t.Fatal(err)
	}
	line, err := readVisibleLine(context.Background(), r)
	if err != nil || len(line) != maxVisibleLine {
		t.Fatalf("got %d bytes, %v", len(line), err)
	}
	if _, err := w.Write([]byte("next\n")); err != nil {
		t.Fatal(err)
	}
	if line, err := readVisibleLine(context.Background(), r); err != nil || line != "next" {
		t.Fatalf("the next line: %q, %v", line, err)
	}
}
