// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build !windows

package safefile

import (
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/deepsecret-io/cli/internal/errs"
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

// OpenAppend opens path to append to it, creating it private to this user
// (0600, the umask applies) when it is missing. A file already there keeps
// its mode.
func OpenAppend(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600) // #nosec G304 G703 -- a path the user chose, such as DS_LOG_PATH.
}

// CreateTemp creates a new file in dir for writing, private to this user
// (0600): it is os.CreateTemp.
func CreateTemp(dir, pattern string) (*os.File, error) {
	return os.CreateTemp(dir, pattern)
}

// MkdirPrivate creates dir and any missing parents, each private to this
// user (0700), as os.MkdirAll does: folders already there keep their mode.
func MkdirPrivate(dir string) error {
	return os.MkdirAll(dir, 0o700)
}

// ReadPrivate reads the file path, and refuses one that another user owns
// or that anyone but its owner may open (ErrNotPrivate), as the Windows
// build does: a key or a credential in it is no longer private, and
// someone else may have put it there. The check and the read use one
// descriptor, so the file cannot be swapped in between.
func ReadPrivate(path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- callers pass the path of a file the CLI keeps.
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read only.
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return nil, errs.WithDetail(&notPrivateError{path: path}, "Another account owns it. Delete it, and let the CLI write it again.")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errs.WithDetail(&notPrivateError{path: path},
			fmt.Sprintf("Other accounts on this computer may open it. To keep it to your account, run:\n  chmod 600 %q", path))
	}
	return io.ReadAll(f)
}
