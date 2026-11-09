// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build !windows

package safefile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deepsecret-io/cli/internal/errs"
)

// A config or token file someone else may open is refused, as it is on
// Windows, with the command that fixes it.
func TestReadPrivateRefusesAnExposedFileUnix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token.json")
	if err := Write(path, []byte(`{"token":"t"}`), 0o600, false); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadPrivate(path); err != nil || string(got) != `{"token":"t"}` {
		t.Fatalf("a private file: %q, %v", got, err)
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		_, err := ReadPrivate(path)
		if !errors.Is(err, ErrNotPrivate) {
			t.Fatalf("mode %o: %v, want ErrNotPrivate", mode, err)
		}
		summary, detail := errs.Describe(err)
		if !strings.HasSuffix(summary, "token.json is open to other users") || !strings.Contains(detail, "may open it") ||
			!strings.Contains(detail, `chmod 600 "`+path+`"`) {
			t.Errorf("mode %o: %q, %q", mode, summary, detail)
		}
	}
	if _, err := ReadPrivate(filepath.Join(t.TempDir(), "missing.json")); !os.IsNotExist(err) {
		t.Errorf("a missing file: %v, want not exist", err)
	}
}
