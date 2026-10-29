// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build !windows

package main

import (
	"os"
	"syscall"
)

// createExclusive creates path with O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW, so
// it never opens a file that is already there, and the kernel rejects a
// symlink at the leaf: an attacker who plants one in the output directory
// cannot redirect plaintext writes. The file gets mode with the umask
// applied.
//
// O_NOFOLLOW only checks the leaf; intermediate components can still be
// symlinks. For deeper hardening (openat-style traversal), see the README.
func createExclusive(path string, mode os.FileMode) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, mode) // #nosec G304 -- the user's own -o path, or a fresh name beside it; O_NOFOLLOW refuses a link at its leaf.
}
