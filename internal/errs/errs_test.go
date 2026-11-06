// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package errs

import (
	"errors"
	"fmt"
	"testing"
)

// An error's first line, with a capital, is the summary; the rest of its
// message and the detail it carries are the detail.
func TestDescribeError(t *testing.T) {
	err := WithDetail(fmt.Errorf("upload interrupted: %w", errors.New("connection reset\n  after 3 attempts")), "The upload can resume:\n  secret resume 7da383f1")
	summary, detail := Describe(err)
	if summary != "Upload interrupted: connection reset" {
		t.Errorf("summary %q", summary)
	}
	if detail != "after 3 attempts\n\nThe upload can resume:\n  secret resume 7da383f1" {
		t.Errorf("detail %q", detail)
	}
}
