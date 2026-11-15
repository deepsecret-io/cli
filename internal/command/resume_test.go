// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/deepsecret-io/deepsecret-go/secrets"
	"github.com/spf13/cobra"

	"github.com/deepsecret-io/cli/internal/auth"
	"github.com/deepsecret-io/cli/internal/errs"
	"github.com/deepsecret-io/cli/internal/pending"
	"github.com/deepsecret-io/cli/internal/testutil"
)

// A kept download is continued by the decrypt it came from: the secret ID
// and --revision from the local record. They come from a local file, so
// they go into those arguments only as the UUIDs they must be.
func TestDownloadDecryptArgs(t *testing.T) {
	d := &secrets.PendingDownload{RevisionID: "7b11d0ab-0000-4000-8000-000000000005", SecretID: "3f2a9c1e-0000-4000-8000-000000000009"}
	args, err := pending.DownloadDecryptArgs(d)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{d.SecretID, "--revision", d.RevisionID}; !slices.Equal(args, want) {
		t.Fatalf("decrypt arguments %q, want %q", args, want)
	}
	for _, bad := range []secrets.PendingDownload{
		{RevisionID: d.RevisionID, SecretID: "x; rm -rf ~"},
		{RevisionID: "--dir=/etc", SecretID: d.SecretID},
		{RevisionID: strings.ToUpper(d.RevisionID), SecretID: d.SecretID},
	} {
		args, err := pending.DownloadDecryptArgs(&bad)
		if err == nil {
			t.Errorf("%+v: decrypt arguments %q, want an error", bad, args)
			continue
		}
		summary, detail := errs.Describe(err)
		if strings.Contains(summary+detail, "rm -rf") || strings.Contains(summary+detail, "/etc") || !strings.Contains(detail, "--discard") {
			t.Errorf("%+v: %q, %q", bad, summary, detail)
		}
	}
}

// Resuming a download runs decrypt with those arguments, flags included:
// with no credentials it gets past decrypt's own checks to signing in. A
// bad secret ID stops at decrypt's argument check.
func TestRunDecrypt(t *testing.T) {
	testutil.SetHome(t, t.TempDir())
	t.Setenv("DS_API_KEY", "")
	// Another test that runs the root command copies DS_API_KEY into
	// auth.FlagKey: clear it, so this test never reaches a server.
	savedKey, savedOrigin := auth.FlagKey, auth.FlagKeyOrigin
	t.Cleanup(func() { auth.FlagKey, auth.FlagKeyOrigin = savedKey, savedOrigin })
	auth.FlagKey, auth.FlagKeyOrigin = "", ""
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	err := runDecrypt(cmd, []string{"3f2a9c1e-0000-4000-8000-000000000009", "--revision", "7b11d0ab-0000-4000-8000-000000000005", "--threads", "8"})
	if err == nil || !strings.Contains(err.Error(), "not logged in") {
		t.Fatalf("a kept download with no credentials: %v, want the sign-in error", err)
	}
	if err := runDecrypt(cmd, []string{"not-a-uuid"}); err == nil || strings.Contains(err.Error(), "not logged in") {
		t.Fatalf("a bad secret ID: %v, want decrypt's argument error", err)
	}
	if err := runDecrypt(cmd, []string{"3f2a9c1e-0000-4000-8000-000000000009", "--threads", "99"}); err == nil || strings.Contains(err.Error(), "not logged in") {
		t.Fatalf("--threads 99: %v, want decrypt's flag error", err)
	}
	// decrypt's own flag groups are checked too, as when it is typed.
	if err := runDecrypt(cmd, []string{"--local", "x.cbor", "--revision", "7b11d0ab-0000-4000-8000-000000000005"}); err == nil || !strings.Contains(err.Error(), "none of the others can be") {
		t.Fatalf("--local with --revision: %v, want decrypt's flag group error", err)
	}
}

// --threads takes what the transfer takes: up to 64 for a download, which
// resume hands to decrypt, and up to 32 for an upload.
func TestResumeThreads(t *testing.T) {
	if err := newResumeCmd().ParseFlags([]string{"--threads", "48"}); err != nil {
		t.Fatalf("--threads 48: %v", err)
	}
	if err := newResumeCmd().ParseFlags([]string{"--threads", "65"}); err == nil {
		t.Fatal("--threads 65 was accepted")
	}
	if err := checkUploadThreads(32); err != nil {
		t.Fatalf("32 upload threads: %v", err)
	}
	if err := checkUploadThreads(48); err == nil || !strings.Contains(err.Error(), "32") {
		t.Fatalf("48 upload threads: %v, want a refusal naming 32", err)
	}
}

// The hint after an interrupted download says resume continues it with
// decrypt's default output.
func TestDownloadResumeDetail(t *testing.T) {
	detail := downloadResumeDetail(secrets.PendingDownload{RevisionID: "7b11d0ab-0000-4000-8000-000000000005", Size: 10, Have: [][2]int64{{0, 4}}})
	if !strings.Contains(detail, "secret resume 7b11d0ab") || !strings.Contains(detail, "default output") {
		t.Fatalf("%q", detail)
	}
}
