// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package testutil holds helpers the CLI's tests share across packages.
package testutil

import (
	"io"
	"os"
	"regexp"
	"testing"
)

// AnsiEscape matches an ANSI escape sequence.
var AnsiEscape = regexp.MustCompile("\033\\[[0-9;]*[A-Za-z]")

// StderrOf runs f with stderr going to a pipe, and returns what it wrote.
func StderrOf(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stderr
	os.Stderr = w
	got := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		got <- string(b)
	}()
	f()
	os.Stderr = saved
	_ = w.Close()
	return <-got
}
