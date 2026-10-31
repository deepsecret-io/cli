// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/deepsecret-io/sdk"
	"github.com/deepsecret-io/sdk/api"
)

// uploadsDir is where large sends keep their encrypted payload until the
// upload finishes, so `secret resume` can finish an interrupted one.
// DEEPSECRET_TMPDIR moves it, as it moves the other temporary files; the
// folder there is named for the user, since that directory may be shared,
// and the SDK refuses it unless it is private to this user.
func uploadsDir() string {
	if dir := os.Getenv(sdk.TempDirEnv); dir != "" {
		return filepath.Join(dir, "deepsecret-uploads-"+userTag())
	}
	return filepath.Join(configDir(), "uploads")
}

// downloadsDir is where large decrypts keep what they downloaded until the
// payload is decrypted, so an interrupted decrypt continues where it
// stopped when run again. DEEPSECRET_TMPDIR moves it, as it moves
// uploadsDir.
func downloadsDir() string {
	if dir := os.Getenv(sdk.TempDirEnv); dir != "" {
		return filepath.Join(dir, "deepsecret-downloads-"+userTag())
	}
	return filepath.Join(configDir(), "downloads")
}

// userTag names this user in a folder name: the numeric user ID on Unix,
// and the account name on Windows, which has no user IDs.
func userTag() string {
	if uid := os.Getuid(); uid >= 0 {
		return strconv.Itoa(uid)
	}
	if u, err := user.Current(); err == nil {
		name := u.Username[strings.LastIndexAny(u.Username, `\/`)+1:] // DOMAIN\name
		name = strings.Map(func(r rune) rune {
			if r < 0x80 && (unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '_' || r == '-') {
				return r
			}
			return '_'
		}, name)
		if name != "" {
			return name
		}
	}
	return "user"
}

// uploadIDPattern is an upload or download ID, or its first 4 or more
// characters.
var uploadIDPattern = regexp.MustCompile(`^[0-9a-f][0-9a-f-]{3,35}$`)

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
			if len(args) == 1 && !uploadIDPattern.MatchString(strings.ToLower(args[0])) {
				return fmt.Errorf("invalid ID %q: give the ID \"secret resume\" lists, or its first 4+ characters", args[0])
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := uploadsDir()
			pending, err := sdk.ListPendingUploads(dir)
			if err != nil {
				return fmt.Errorf("could not list the interrupted uploads: %w", err)
			}
			downloads, err := sdk.ListPendingDownloads(downloadsDir())
			if err != nil {
				return fmt.Errorf("could not list the interrupted downloads: %w", err)
			}
			if len(args) == 0 {
				if discard {
					return fmt.Errorf("--discard needs the ID of the upload or download to discard")
				}
				return printPendingTransfers(pending, downloads)
			}
			p, d, err := findPending(pending, downloads, args[0])
			if err != nil {
				return err
			}
			if d != nil {
				return discardDownload(d, discard)
			}
			c, err := newAuthenticatedClient()
			if err != nil {
				return err
			}

			if discard {
				discardStep := step{label: "Discarding the upload of " + p.Name, done: "Upload discarded", action: func() (string, error) {
					if err := c.DiscardPendingUpload(dir, p.RevisionID); err != nil {
						return "", err
					}
					api.Module(logger, "resume").Info("upload discarded", "revision_id", p.RevisionID, "secret_id", p.SecretID)
					return "", nil
				}}
				return runPipeline("upload", []step{discardStep})
			}

			progress := newUploadProgress()
			uploadStep := step{
				label: "Uploading " + p.Name,
				done:  "Upload complete",
				live:  progress,
				action: func() (string, error) {
					_, err := c.ResumeUpload(dir, p.RevisionID, sdk.ResumeOptions{
						UploadThreads: threads,
						UploadStatus:  &progress.transfer,
						Logger:        logger,
					})
					if err != nil {
						return "", err
					}
					return "id=" + shortID(p.SecretID), nil
				},
			}
			if err := runPipeline("upload", []step{uploadStep}); err != nil {
				var interrupted *sdk.UploadInterruptedError
				if errors.As(err, &interrupted) {
					return withDetail(err, resumeDetail(interrupted.Upload.RevisionID))
				}
				return err
			}
			fmt.Fprintln(os.Stderr)
			printKeyValue("Secret ID", safe(p.SecretID))
			printKeyValue("Name", safe(p.Name))
			printKeyValue("Size", formatBytes(p.Size)+" encrypted")
			fmt.Fprintln(os.Stderr)
			return nil
		},
	}
	f := cmd.Flags()
	f.BoolVar(&discard, "discard", false, "Discard the interrupted upload or download instead of finishing it, deleting what it kept")
	setGroup(f, groupOptions, "discard")
	f.Var(newIntRange(&threads, 0, 0, api.MaxUploadThreads, " (0 adapts to the connection, 1 is one at a time)"), "threads", "Parallel part uploads: 0 adapts to the connection, up to 32")
	setGroup(f, groupPerformance, "threads")
	cmd.MarkFlagsMutuallyExclusive("discard", "threads")
	return cmd
}

// findPending picks the interrupted upload or download whose ID is, or
// starts with, id; one of the two results is set.
func findPending(uploads []sdk.PendingUpload, downloads []sdk.PendingDownload, id string) (*sdk.PendingUpload, *sdk.PendingDownload, error) {
	id = strings.ToLower(strings.TrimSpace(id))
	var up []*sdk.PendingUpload
	var down []*sdk.PendingDownload
	for i := range uploads {
		switch p := &uploads[i]; {
		case p.RevisionID == id:
			return p, nil, nil
		case len(id) >= 4 && strings.HasPrefix(p.RevisionID, id):
			up = append(up, p)
		}
	}
	for i := range downloads {
		switch d := &downloads[i]; {
		case d.RevisionID == id:
			return nil, d, nil
		case len(id) >= 4 && strings.HasPrefix(d.RevisionID, id):
			down = append(down, d)
		}
	}
	switch n := len(up) + len(down); {
	case n == 0:
		return nil, nil, withDetail(fmt.Errorf("no interrupted upload or download %q", id), "List them with: secret resume")
	case n > 1:
		return nil, nil, fmt.Errorf("%q matches %d transfers; give more of the ID", id, n)
	case len(up) == 1:
		return up[0], nil, nil
	default:
		return nil, down[0], nil
	}
}

// discardDownload removes a kept download with --discard. Without it, it
// says how to continue the download: by decrypting again, which keeps the
// decrypt's own output choices.
func discardDownload(d *sdk.PendingDownload, discard bool) error {
	if !discard {
		detail := "A download continues when you decrypt it again."
		// The secret ID comes from a local file: it goes into a command
		// to copy only as the UUID it must be.
		if id, err := uuid.Parse(d.SecretID); err == nil && id.String() == d.SecretID {
			detail = "A download continues when you decrypt it again:\n  secret decrypt " + d.SecretID + " --revision " + d.RevisionID
		}
		return withDetail(fmt.Errorf("%s is an interrupted download, which resume does not finish", shortID(d.RevisionID)), detail)
	}
	if err := sdk.DiscardPendingDownload(downloadsDir(), d.RevisionID); err != nil {
		return fmt.Errorf("could not discard the download of %q: %w", d.Name, err)
	}
	api.Module(logger, "resume").Info("download discarded", "revision_id", d.RevisionID, "secret_id", d.SecretID)
	printSuccess(fmt.Sprintf("Discarded the download of %q.", d.Name))
	return nil
}

func printPendingTransfers(uploads []sdk.PendingUpload, downloads []sdk.PendingDownload) error {
	if len(uploads) == 0 && len(downloads) == 0 {
		fmt.Fprintln(os.Stderr)
		printDim("No interrupted uploads or downloads.")
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

func printPendingDownloads(downloads []sdk.PendingDownload) error {
	printHeader(fmt.Sprintf("Interrupted downloads (%d)", len(downloads)))
	fmt.Fprintln(os.Stderr)
	// Rows wait in the tabwriter until Flush, which returns any write error.
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintf(w, "  ID\tNAME\tDOWNLOADED\tLAST ACTIVITY\n")
	_, _ = fmt.Fprintf(w, "  --\t----\t----------\t-------------\n")
	for _, d := range downloads {
		got := fmt.Sprintf("%s of %s", formatBytes(d.Downloaded()), formatBytes(d.Size))
		if d.Downloaded() == d.Size {
			got = formatBytes(d.Size) + ", not decrypted"
		}
		_, _ = fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", safe(shortID(d.RevisionID)), safe(d.Name), got, ago(d.UpdatedAt))
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("could not write to stdout: %w", err)
	}
	fmt.Fprintln(os.Stderr)
	printDim("A download continues when you decrypt it again ('secret resume <id>' shows the command).")
	printDim("Discard one with: secret resume <id> --discard")
	fmt.Fprintln(os.Stderr)
	return nil
}

// downloadResumeDetail says how to continue an interrupted download, for
// its Error block.
func downloadResumeDetail(d sdk.PendingDownload) string {
	return fmt.Sprintf("Run the same command again to continue the download, keeping the %s downloaded so far.", formatBytes(d.Downloaded()))
}

func printPendingUploads(pending []sdk.PendingUpload) error {
	printHeader(fmt.Sprintf("Interrupted uploads (%d)", len(pending)))
	fmt.Fprintln(os.Stderr)
	// Rows wait in the tabwriter until Flush, which returns any write error.
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintf(w, "  ID\tNAME\tSIZE\tLAST ACTIVITY\n")
	_, _ = fmt.Fprintf(w, "  --\t----\t----\t-------------\n")
	for _, p := range pending {
		activity := ago(p.UpdatedAt)
		if time.Since(p.UpdatedAt) > uploadIdleLimit {
			activity += " (likely dropped by the server)"
		}
		_, _ = fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", safe(shortID(p.RevisionID)), safe(p.Name), formatBytes(p.Size), activity)
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("could not write to stdout: %w", err)
	}
	fmt.Fprintln(os.Stderr)
	printDim("Finish one with: secret resume <id>")
	printDim("Discard one with: secret resume <id> --discard")
	fmt.Fprintln(os.Stderr)
	return nil
}

// resumeDetail says how to finish an interrupted upload, for its Error
// block.
func resumeDetail(revisionID string) string {
	return "To finish it, keeping the parts already sent, run:\n  secret resume " + shortID(revisionID)
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
