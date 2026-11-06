// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/deepsecret-io/deepsecret-go/secrets"
	"github.com/deepsecret-io/deepsecret-go/transfer"
	"github.com/spf13/cobra"

	"github.com/deepsecret-io/cli/internal/auth"
	"github.com/deepsecret-io/cli/internal/console"
	"github.com/deepsecret-io/cli/internal/errs"
	"github.com/deepsecret-io/cli/internal/flags"
	"github.com/deepsecret-io/cli/internal/logging"
	"github.com/deepsecret-io/cli/internal/pending"
	"github.com/deepsecret-io/cli/internal/ui"
)

// uploadIdleLimit is how long the server keeps an upload without activity.
const uploadIdleLimit = 24 * time.Hour

func newResumeCmd() *cobra.Command {
	var (
		discard bool
		threads int
	)
	cmd := &cobra.Command{
		Use:   "resume [id]",
		Short: "Finish or discard an interrupted upload, or list interrupted transfers",
		Long: `A large send keeps its encrypted payload until its upload finishes. If the
upload is interrupted (network loss, Ctrl+C, a closed laptop), finish it here:
the parts already uploaded are kept and the rest are sent. Nothing is
encrypted again.

A large decrypt keeps what it downloaded the same way, until the payload is
decrypted. Run the same decrypt again to continue an interrupted download:
only the missing ranges are fetched.

Without an ID, lists the interrupted uploads and downloads. The server drops an
upload after a day without activity; discard it then and send again. A
download unused for a week is removed.`,
		Example: `  secret resume
  secret resume 3f2a9c1e
  secret resume 3f2a9c1e --discard`,
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.MaximumNArgs(1)(cmd, args); err != nil {
				return err
			}
			if len(args) == 1 && !pending.UploadIDPattern.MatchString(strings.ToLower(args[0])) {
				return fmt.Errorf("invalid ID %q: give the ID \"secret resume\" lists, or its first 4+ characters", args[0])
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := pending.UploadsDir()
			uploads, err := secrets.ListPendingUploads(dir)
			if err != nil {
				return fmt.Errorf("could not list the interrupted uploads: %w", err)
			}
			downloads, err := secrets.ListPendingDownloads(pending.DownloadsDir())
			if err != nil {
				return fmt.Errorf("could not list the interrupted downloads: %w", err)
			}
			if len(args) == 0 {
				if discard {
					return fmt.Errorf("--discard needs the ID of the upload or download to discard")
				}
				return printPendingTransfers(uploads, downloads)
			}
			p, d, err := pending.Find(uploads, downloads, args[0])
			if err != nil {
				return err
			}
			if d != nil {
				return pending.DiscardDownload(d, discard)
			}
			c, err := auth.NewAuthenticatedClient()
			if err != nil {
				return err
			}

			if discard {
				discardStep := ui.Step{Label: "Discarding the upload of " + p.Name, Done: "Upload discarded", Action: func() (string, error) {
					if err := c.Secrets.DiscardPendingUpload(cmd.Context(), dir, p.RevisionID); err != nil {
						return "", err
					}
					logging.Module(logging.Log, "resume").Info("upload discarded", "revision_id", p.RevisionID, "secret_id", p.SecretID)
					return "", nil
				}}
				return ui.RunPipeline(cmd.Context(), "upload", []ui.Step{discardStep})
			}

			progress := ui.NewUploadProgress()
			uploadStep := ui.Step{
				Label: "Uploading " + p.Name,
				Done:  "Upload complete",
				Live:  progress,
				Action: func() (string, error) {
					_, err := c.Secrets.ResumeUpload(cmd.Context(), dir, p.RevisionID, secrets.ResumeOptions{
						UploadThreads: threads,
						UploadStatus:  &progress.Transfer,
						Logger:        logging.Log,
					})
					if err != nil {
						return "", err
					}
					return "id=" + ui.ShortID(p.SecretID), nil
				},
			}
			if err := ui.RunPipeline(cmd.Context(), "upload", []ui.Step{uploadStep}); err != nil {
				var interrupted *secrets.UploadInterruptedError
				if errors.As(err, &interrupted) {
					return errs.WithDetail(err, resumeDetail(interrupted.Upload.RevisionID))
				}
				return err
			}
			fmt.Fprintln(os.Stderr)
			ui.KeyValue("Secret ID", console.Safe(p.SecretID))
			ui.KeyValue("Name", console.Safe(p.Name))
			ui.KeyValue("Size", ui.FormatBytes(p.Size)+" encrypted")
			fmt.Fprintln(os.Stderr)
			return nil
		},
	}
	f := cmd.Flags()
	f.BoolVar(&discard, "discard", false, "Discard the interrupted upload or download instead of finishing it, deleting what it kept")
	flags.SetGroup(f, flags.GroupOptions, "discard")
	f.Var(flags.NewIntRange(&threads, 0, 0, transfer.MaxUploadThreads, " (0 adapts to the connection, 1 is one at a time)"), "threads", "Parallel part uploads: 0 adapts to the connection, up to 32")
	flags.SetGroup(f, flags.GroupPerformance, "threads")
	cmd.MarkFlagsMutuallyExclusive("discard", "threads")
	return cmd
}

func printPendingTransfers(uploads []secrets.PendingUpload, downloads []secrets.PendingDownload) error {
	if len(uploads) == 0 && len(downloads) == 0 {
		fmt.Fprintln(os.Stderr)
		ui.Dimmed("No interrupted uploads or downloads.")
		fmt.Fprintln(os.Stderr)
		return nil
	}
	if len(uploads) > 0 {
		if err := printPendingUploads(uploads); err != nil {
			return err
		}
	}
	if len(downloads) > 0 {
		return printPendingDownloads(downloads)
	}
	return nil
}

func printPendingDownloads(downloads []secrets.PendingDownload) error {
	ui.Header(fmt.Sprintf("Interrupted downloads (%d)", len(downloads)))
	fmt.Fprintln(os.Stderr)
	// Rows wait in the tabwriter until Flush, which returns any write error.
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintf(w, "  ID\tNAME\tDOWNLOADED\tLAST ACTIVITY\n")
	_, _ = fmt.Fprintf(w, "  --\t----\t----------\t-------------\n")
	for _, d := range downloads {
		got := fmt.Sprintf("%s of %s", ui.FormatBytes(d.Downloaded()), ui.FormatBytes(d.Size))
		if d.Downloaded() == d.Size {
			got = ui.FormatBytes(d.Size) + ", not decrypted"
		}
		_, _ = fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", console.Safe(ui.ShortID(d.RevisionID)), console.Safe(d.Name), got, ui.Ago(d.UpdatedAt))
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("could not write to stdout: %w", err)
	}
	fmt.Fprintln(os.Stderr)
	ui.Dimmed("A download continues when you decrypt it again ('secret resume <id>' shows the command).")
	ui.Dimmed("Discard one with: secret resume <id> --discard")
	fmt.Fprintln(os.Stderr)
	return nil
}

// downloadResumeDetail says how to continue an interrupted download, for
// its Error block.
func downloadResumeDetail(d secrets.PendingDownload) string {
	return fmt.Sprintf("Run the same command again to continue the download, keeping the %s downloaded so far.", ui.FormatBytes(d.Downloaded()))
}

func printPendingUploads(uploads []secrets.PendingUpload) error {
	ui.Header(fmt.Sprintf("Interrupted uploads (%d)", len(uploads)))
	fmt.Fprintln(os.Stderr)
	// Rows wait in the tabwriter until Flush, which returns any write error.
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintf(w, "  ID\tNAME\tSIZE\tLAST ACTIVITY\n")
	_, _ = fmt.Fprintf(w, "  --\t----\t----\t-------------\n")
	for _, p := range uploads {
		activity := ui.Ago(p.UpdatedAt)
		if time.Since(p.UpdatedAt) > uploadIdleLimit {
			activity += " (likely dropped by the server)"
		}
		_, _ = fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", console.Safe(ui.ShortID(p.RevisionID)), console.Safe(p.Name), ui.FormatBytes(p.Size), activity)
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("could not write to stdout: %w", err)
	}
	fmt.Fprintln(os.Stderr)
	ui.Dimmed("Finish one with: secret resume <id>")
	ui.Dimmed("Discard one with: secret resume <id> --discard")
	fmt.Fprintln(os.Stderr)
	return nil
}

// resumeDetail says how to finish an interrupted upload, for its Error
// block.
func resumeDetail(revisionID string) string {
	return "To finish it, keeping the parts already sent, run:\n  secret resume " + ui.ShortID(revisionID)
}
