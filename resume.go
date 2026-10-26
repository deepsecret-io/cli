// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/deepsecret-io/sdk"
)

// uploadsDir is where large sends keep their encrypted payload until the
// upload finishes, so `secret resume` can finish an interrupted one.
// DEEPSECRET_TMPDIR moves it, as it moves the other temporary files.
func uploadsDir() string {
	if dir := os.Getenv(sdk.TempDirEnv); dir != "" {
		return filepath.Join(dir, "deepsecret-uploads")
	}
	return filepath.Join(configDir(), "uploads")
}

// uploadIdleLimit is how long the server keeps an upload without activity.
const uploadIdleLimit = 24 * time.Hour

func newResumeCmd() *cobra.Command {
	var (
		discard bool
		threads int
	)
	cmd := &cobra.Command{
		Use:   "resume [upload-id]",
		Short: "Finish an interrupted upload, or list them",
		Long: `A large send keeps its encrypted payload until its upload finishes. If the
upload is interrupted (network loss, Ctrl+C, a closed laptop), finish it here:
the parts already uploaded are kept and the rest are sent. Nothing is
encrypted again.

Without an ID, lists the interrupted uploads. The server drops an upload after
a day without activity; discard it then and send again.`,
		Example: `  secret resume
  secret resume 3f2a9c1e
  secret resume 3f2a9c1e --discard`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := uploadsDir()
			pending, err := sdk.ListPendingUploads(dir)
			if err != nil {
				return fmt.Errorf("list interrupted uploads: %w", err)
			}
			if len(args) == 0 {
				if discard {
					return fmt.Errorf("--discard needs the ID of the upload to discard")
				}
				printPendingUploads(pending)
				return nil
			}
			p, err := findPendingUpload(pending, args[0])
			if err != nil {
				return err
			}
			c, err := newAuthenticatedClient()
			if err != nil {
				return err
			}

			if discard {
				discardStep := step{label: "Discarding the upload", action: func() (string, error) {
					return "", c.DiscardPendingUpload(dir, p.RevisionID)
				}}
				if err := runPipeline("Discard Upload", []step{discardStep}, nil); err != nil {
					return err
				}
				printSuccess(fmt.Sprintf("Discarded the upload of %q", p.Name))
				return nil
			}

			progress := &transferProgress{}
			uploadStep := step{
				label:    "Uploading " + p.Name,
				transfer: progress,
				action: func() (string, error) {
					progress.startedAt = time.Now()
					_, err := c.ResumeUpload(dir, p.RevisionID, sdk.ResumeOptions{
						UploadThreads: threads,
						OnUploadProgress: func(transferred, total int64) {
							progress.transferred.Store(transferred)
							progress.total = total
						},
						OnDebug: func(step, msg string) { logDebug(step, "%s", msg) },
					})
					if err != nil {
						return "", err
					}
					return "size=" + formatBytes(p.Size), nil
				},
			}
			if err := runPipeline("Resume Upload", []step{uploadStep}, nil); err != nil {
				var interrupted *sdk.UploadInterruptedError
				if errors.As(err, &interrupted) {
					printResumeHint(interrupted.Upload.RevisionID)
				}
				return err
			}
			fmt.Fprintln(os.Stderr)
			printSuccess(fmt.Sprintf("Sent %q", p.Name))
			printKeyValue("Secret ID", p.SecretID)
			fmt.Fprintln(os.Stderr)
			return nil
		},
	}
	cmd.Flags().BoolVar(&discard, "discard", false, "Abort the upload and delete its encrypted payload")
	cmd.Flags().IntVar(&threads, "threads", 0, "Parallel part uploads (0 = adapt to the connection, max 32)")
	return cmd
}

// findPendingUpload picks the upload whose ID is, or starts with, id.
func findPendingUpload(pending []sdk.PendingUpload, id string) (*sdk.PendingUpload, error) {
	id = strings.ToLower(strings.TrimSpace(id))
	var found []sdk.PendingUpload
	for _, p := range pending {
		if p.RevisionID == id {
			return &p, nil
		}
		if len(id) >= 4 && strings.HasPrefix(p.RevisionID, id) {
			found = append(found, p)
		}
	}
	switch len(found) {
	case 1:
		return &found[0], nil
	case 0:
		return nil, fmt.Errorf("no interrupted upload %q. Run: secret resume", id)
	default:
		return nil, fmt.Errorf("%q matches %d uploads; give more of the ID", id, len(found))
	}
}

func printPendingUploads(pending []sdk.PendingUpload) {
	if len(pending) == 0 {
		fmt.Fprintln(os.Stderr)
		printDim("No interrupted uploads.")
		fmt.Fprintln(os.Stderr)
		return
	}
	printHeader(fmt.Sprintf("Interrupted uploads (%d)", len(pending)))
	fmt.Fprintln(os.Stderr)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "  ID\tNAME\tSIZE\tLAST ACTIVITY\n")
	fmt.Fprintf(w, "  --\t----\t----\t-------------\n")
	for _, p := range pending {
		activity := ago(p.UpdatedAt)
		if time.Since(p.UpdatedAt) > uploadIdleLimit {
			activity += " (likely dropped by the server)"
		}
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", shortID(p.RevisionID), p.Name, formatBytes(p.Size), activity)
	}
	w.Flush()
	fmt.Fprintln(os.Stderr)
	printDim("Resume with: secret resume <id>    Discard with: secret resume <id> --discard")
	fmt.Fprintln(os.Stderr)
}

// printResumeHint says how to finish an interrupted upload.
func printResumeHint(revisionID string) {
	fmt.Fprintf(os.Stderr, "  Tip: the upload can be resumed, keeping the parts already sent:\n")
	fmt.Fprintf(os.Stderr, "       secret resume %s\n", shortID(revisionID))
}

// ago renders how long ago t was.
func ago(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}
