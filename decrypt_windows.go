// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build windows

package main

import (
	"fmt"
	"os"
)

// createExclusive creates path with O_CREAT|O_EXCL|O_WRONLY, so it never
// opens a file that is already there. Windows has no O_NOFOLLOW; symlink
// hardening on Windows would require GetFileAttributes + reparse-point
// inspection on each path component, which we do not implement. For
// security-sensitive deployments, prefer running on Unix where O_NOFOLLOW
// is enforced (see decrypt_unix.go).
func createExclusive(path string, mode os.FileMode) (*os.File, error) {
	// Refuse a symlink or junction at path before opening it.
	if info, err := os.Lstat(path); err == nil && info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return nil, fmt.Errorf("%s is a link: refusing to write through it", path)
	}
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode) // #nosec G304 -- the user's own -o path, or a fresh name beside it; links at it are refused above.
}
