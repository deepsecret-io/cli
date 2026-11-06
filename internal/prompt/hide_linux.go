// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package prompt

import "golang.org/x/sys/unix"

// The requests that read and set a terminal's settings.
const (
	ioctlGetTermios = unix.TCGETS
	ioctlSetTermios = unix.TCSETS
)
