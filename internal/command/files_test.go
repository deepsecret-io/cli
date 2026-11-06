// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"os"
	"testing"

	"github.com/deepsecret-io/cli/internal/console"
)

// Decrypted output that cannot be written to stdout fails the command
// instead of reporting success with part of the secret.
func TestWriteStdoutReportsFailure(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	w.Close()
	stdout := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = stdout }()
	for _, terminal := range []bool{false, true} {
		saved := console.StdoutIsTerminal
		console.StdoutIsTerminal = terminal
		err := writeStdout([]byte("secret"))
		console.StdoutIsTerminal = saved
		if err == nil {
			t.Errorf("terminal=%v: writing to a closed stdout succeeded", terminal)
		}
	}
}
