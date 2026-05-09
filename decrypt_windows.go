// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build windows

package main

import (
	"fmt"
	"os"
)

// safeWriteFile opens dest with O_CREAT|O_WRONLY (plus O_EXCL or O_TRUNC
// depending on force) and writes data. Windows has no O_NOFOLLOW; symlink
// hardening on Windows would require GetFileAttributes + reparse-point
// inspection on each path component, which we do not implement. For
// security-sensitive deployments, prefer running on Unix where O_NOFOLLOW
// is enforced (see decrypt_unix.go).
func safeWriteFile(dest string, data []byte, mode os.FileMode, force bool) error {
	flags := os.O_CREATE | os.O_WRONLY
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
