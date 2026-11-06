// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"strings"
	"testing"

	"github.com/deepsecret-io/deepsecret-go/secrets"

	"github.com/deepsecret-io/cli/internal/errs"
	"github.com/deepsecret-io/cli/internal/pending"
)

// Asked to resume a download, the command says how to continue it, and
// puts the secret ID from the local record into that command only when it
// is a UUID.
func TestResumeExplainsADownload(t *testing.T) {
	d := &secrets.PendingDownload{RevisionID: "7b11d0ab-0000-4000-8000-000000000005", SecretID: "3f2a9c1e-0000-4000-8000-000000000009"}
	err := pending.DiscardDownload(d, false)
	if err == nil {
		t.Fatal("no error for a download")
	}
	if summary, detail := errs.Describe(err); !strings.HasPrefix(summary, "7b11d0ab is an interrupted download") ||
		!strings.Contains(detail, "secret decrypt 3f2a9c1e-0000-4000-8000-000000000009 --revision 7b11d0ab-0000-4000-8000-000000000005") {
		t.Fatalf("continue hint: %q, %q", summary, detail)
	}
	d.SecretID = "x; rm -rf ~"
	err = pending.DiscardDownload(d, false)
	if summary, detail := errs.Describe(err); err == nil || strings.Contains(summary+detail, "rm -rf") {
		t.Fatalf("a hostile secret ID reached the command: %q, %q", summary, detail)
	}
}
