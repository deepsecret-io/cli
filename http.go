// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"sync/atomic"
	"time"
)

// ── Progress tracking (CLI-specific TUI feature) ─────────────────────────────

// transferProgress tracks bytes transferred for live progress display.
type transferProgress struct {
	transferred atomic.Int64
	total       int64
	startedAt   time.Time
}

func (tp *transferProgress) Pct() float64 {
	if tp.total <= 0 {
		return 0
	}
	return float64(tp.transferred.Load()) / float64(tp.total)
}

func (tp *transferProgress) Speed() string {
	elapsed := time.Since(tp.startedAt).Seconds()
	if elapsed < 0.1 {
		return ""
	}
	bps := float64(tp.transferred.Load()) / elapsed
	return formatBytes(int64(bps)) + "/s"
}
