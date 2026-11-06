// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package safefile writes files without following links or leaving partial
// files behind.
package safefile

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"

	"github.com/deepsecret-io/cli/internal/errs"
)

// Write writes decrypted data to dest, created with mode (the umask
// applies) by the platform's createExclusive. Without force it refuses a
// dest that exists. With force it writes a new file beside dest and renames
// it over dest once complete, so dest gets mode instead of keeping an old
// file's, a link at dest is replaced rather than written through, and a
// reader never sees half a file.
func Write(dest string, data []byte, mode os.FileMode, force bool) error {
	if !force {
		f, err := createExclusive(dest, mode)
		if err != nil {
			if os.IsExist(err) {
				return errs.WithDetail(fmt.Errorf("%s already exists", dest), "Pass --overwrite to replace it.")
			}
			return fmt.Errorf("could not create %s: %w", dest, errs.PathCause(err))
		}
		return writeAndClose(f, dest, data)
	}
	tmp := filepath.Join(filepath.Dir(dest), ".deepsecret-"+rand.Text()+".partial")
	f, err := createExclusive(tmp, mode)
	if err != nil {
		return fmt.Errorf("could not create %s: %w", tmp, errs.PathCause(err))
	}
	if err := writeAndClose(f, tmp, data); err != nil {
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		if rmErr := os.Remove(tmp); rmErr != nil {
			return errs.WithDetail(fmt.Errorf("could not replace %s: %w", dest, errs.PathCause(err)),
				fmt.Sprintf("The decrypted content is left in %s, which could not be removed (%v). Delete it.", tmp, errs.PathCause(rmErr)))
		}
		return fmt.Errorf("could not replace %s: %w", dest, errs.PathCause(err))
	}
	return nil
}

// writeAndClose writes data to f, opened at dest, and closes it. On a
// failure it removes dest, so no partly written plaintext stays behind,
// and says so when the removal fails too.
func writeAndClose(f *os.File, dest string, data []byte) error {
	_, err := f.Write(data)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		return nil
	}
	if rmErr := os.Remove(dest); rmErr != nil {
		return errs.WithDetail(fmt.Errorf("could not write %s: %w", dest, errs.PathCause(err)),
			fmt.Sprintf("The partly written file could not be removed (%v). Delete it.", errs.PathCause(rmErr)))
	}
	return fmt.Errorf("could not write %s: %w", dest, errs.PathCause(err))
}
