// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build !windows

package main

import (
	"fmt"
	"os"
	"syscall"
)

// safeWriteFile opens dest with O_CREAT|O_WRONLY|O_NOFOLLOW (plus O_EXCL or
// O_TRUNC depending on force) and writes data. O_NOFOLLOW makes the kernel
// reject the open if dest's leaf component is a symlink, so an attacker who
// plants a symlink in outputDir cannot redirect plaintext writes.
//
// O_NOFOLLOW only checks the leaf; intermediate components can still be
// symlinks. For deeper hardening (openat-style traversal), see the README.
func safeWriteFile(dest string, data []byte, mode os.FileMode, force bool) error {
	flags := os.O_CREATE | os.O_WRONLY | syscall.O_NOFOLLOW
	if force {
		flags |= os.O_TRUNC
	} else {
		flags |= os.O_EXCL
	}
	f, err := os.OpenFile(dest, flags, mode)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("refusing to overwrite %q (use --force)", dest)
		}
		return fmt.Errorf("open %s: %w", dest, err)
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write %s: %w", dest, err)
	}
	return nil
}
