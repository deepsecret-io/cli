// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build windows

package prompt

import (
	"os"
	"path/filepath"
	"testing"
)

// Pipes and files are not a console, so a process whose stdin, stdout and
// stderr are all redirected, as on a CI runner, gets no terminal and its
// prompt falls back to stdin, instead of waiting on a hidden console.
func TestAnyConsoleRefusesPipesAndFiles(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close(); _ = r.Close() })
	f, err := os.Create(filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if anyConsole(r, w, f, nil) {
		t.Fatal("a pipe or a file was taken for a console")
	}
}
