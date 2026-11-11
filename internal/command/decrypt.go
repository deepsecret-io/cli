// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/deepsecret-io/deepsecret-go/keys"
	"github.com/deepsecret-io/deepsecret-go/secrets"
	"github.com/deepsecret-io/deepsecret-go/transfer"
	"github.com/deepsecret-io/deepsecret-go/trust"
	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/deepsecret-io/cli/internal/auth"
	"github.com/deepsecret-io/cli/internal/console"
	"github.com/deepsecret-io/cli/internal/errs"
	"github.com/deepsecret-io/cli/internal/flags"
	"github.com/deepsecret-io/cli/internal/identity"
	"github.com/deepsecret-io/cli/internal/logging"
	"github.com/deepsecret-io/cli/internal/pending"
	"github.com/deepsecret-io/cli/internal/safefile"
	"github.com/deepsecret-io/cli/internal/ui"
)

// forceOverwrite is wired from the --overwrite flag in newDecryptCmd. When false,
// existing destination files cause writes to fail (O_EXCL); when true, they
// are replaced by a new file renamed over them (safefile.Write). A link at
// a created file's leaf is rejected (O_NOFOLLOW on Unix, an open that does
// not follow reparse points on Windows), so an attacker who can plant one
// in outputDir cannot redirect plaintext writes, and on Windows the file
// gets an owner-only ACL; see createExclusive in safefile/private_unix.go
// and safefile/private_windows.go.
var forceOverwrite bool

func newDecryptCmd() *cobra.Command {
	var (
		outputDir       string
		outputFile      string
		revisionID      string
		identityFP      string
		useRecoveryCode bool
		downloadThreads int
		presignExpiry   int
		local           bool
	)

	cmd := &cobra.Command{
		Use:     "decrypt <secret-id> | decrypt --local <file>",
		Aliases: []string{"dec"},
		Short:   "Decrypt a secret (alias: dec)",
		Long: `Decrypt a secret. Where the output goes depends on what it holds:
  - Files are written to a directory named after the revision ID by default,
    so a decrypt never writes over files in the current directory. --dir
    chooses another one.
  - A message or key-value data is printed to stdout, or written to the
    file --output names.

--local decrypts a file written by "secret encrypt --local" instead of a
secret on the server. Only public keys are looked up: it checks that the
sender named in the file registered the key that signed it, then verifies
and decrypts it on this machine.

Large secrets download in parallel ranges, adapting the connections to the
link. --progress shows each connection as it goes, and --debug the transfer
plan and every change to it.`,
		Example: `  secret decrypt 3f2a9c1e-...                    # files go to ./<revision-id>/
  secret decrypt 3f2a9c1e-... --dir ./out
  secret decrypt 3f2a9c1e-... -o db.env          # a message or data, to a file
  secret decrypt 3f2a9c1e-... -r 7b1d...         # a specific revision
  secret decrypt --local db.env.cbor             # a file sent to you directly`,
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.ExactArgs(1)(cmd, args); err != nil {
				return err
			}
			if local {
				return nil
			}
			return flags.CheckIDs(args, "secret ID")
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			secretID, localPath := args[0], ""
			if local {
				secretID, localPath = "", args[0]
				info, err := os.Stat(localPath)
				if err != nil {
					return fmt.Errorf("could not read %s: %w", localPath, errs.PathCause(err))
				}
				if !info.Mode().IsRegular() {
					return fmt.Errorf("%s is not a file", localPath)
				}
			}

			// Validate an explicit --dir up front. The empty default is resolved
			// later to the revision UUID once the SDK has fetched the secret;
			// we cannot create that directory now because we don't know the
			// revision ID yet.
			if outputDir != "" {
				if info, err := os.Stat(outputDir); err != nil {
					if err := safefile.MkdirPrivate(outputDir); err != nil {
						return fmt.Errorf("could not create the output directory %s: %w", outputDir, errs.PathCause(err))
					}
				} else if !info.IsDir() {
					return fmt.Errorf("--dir %s is not a directory", outputDir)
				}
			}
			if outputFile != "" {
				if err := flags.CheckOutputFile("output", outputFile); err != nil {
					return err
				}
			}

			c, err := auth.NewAuthenticatedClient()
			if err != nil {
				return err
			}

			// Without --identity, pick the key the target revision (or the
			// file) was sealed with for the caller: the user may have
			// changed their primary key, and still hold the older keys that
			// older revisions were sealed for. Otherwise the primary key
			// opens it.
			idLog := logging.Module(logging.Log, "identity")
			identitySource := "primary"
			// The secret and its revisions, once fetched here, go to the
			// SDK, which does not fetch them again.
			var fetched *secrets.Detail
			switch {
			case identityFP != "":
				identitySource = "--identity"
			case local:
				rs, err := secrets.LocalFileRecipients(localPath)
				if err != nil {
					// Opening the file reports what is wrong with it.
					idLog.Debug("key selection skipped", "reason", "the file's recipients could not be read", "error", err)
				}
				for _, r := range rs {
					if matched := identity.FindLocal(r.Fingerprint); matched != "" {
						identityFP, identitySource = matched, "sealed for"
						break
					}
				}
			default:
				detail, err := c.Secrets.DescribeFull(cmd.Context(), secretID)
				if err != nil {
					return secretError(err, secretID)
				}
				fetched = detail
				actorID, err := c.Identity.ResolveActorID(cmd.Context())
				if err != nil {
					idLog.Warn("key selection skipped", "reason", "your account ID could not be fetched", "error", err)
					break
				}
				expected := revisionKey(detail, revisionID, actorID)
				switch matched := identity.FindLocal(expected); {
				case matched != "":
					identityFP, identitySource = matched, "sealed for"
				case expected != "":
					idLog.Debug("revision key not on this device", "fingerprint", expected, "using", "primary key")
				}
			}

			// The settings this decrypt resolved to, once, before the SDK
			// logs its own plan.
			settings := []any{"identity", identityLabel(identityFP), "identity_source", identitySource}
			if local {
				settings = append(settings, "local_file", localPath)
			} else {
				revision := revisionID
				if revision == "" {
					revision = "latest"
				}
				settings = append(settings, "secret_id", secretID, "revision", revision,
					"threads", ui.ThreadCountLabel(downloadThreads), "presign_expiry", time.Duration(presignExpiry)*time.Minute)
			}
			if outputDir != "" {
				settings = append(settings, "dir", outputDir)
			}
			if outputFile != "" {
				settings = append(settings, "output", outputFile)
			}
			logging.Module(logging.Log, "decrypt").Debug("options", settings...)

			// Ask for what the key pair needs: its password, or its recovery
			// code; a security key is asked for its PIN and a touch when used.
			unlock, err := commandUnlock(cmd.Context(), c, identityFP, useRecoveryCode)
			if err != nil {
				return err
			}

			// Build SDK options
			opts := secrets.DecryptOptions{
				Revision:             revisionID,
				Secret:               fetched,
				Identity:             identityFP,
				Unlock:               unlock,
				DownloadThreads:      downloadThreads,
				PresignExpiryMinutes: presignExpiry,
				Logger:               logging.Log,
				// The download can be large: check that the files can be
				// written before fetching them.
				BeforeDownload: func(p secrets.UpcomingDownload) error {
					if p.PayloadType != "files" {
						return nil
					}
					return checkFilesDestination(outputDir, p, forceOverwrite)
				},
			}

			// Live progress: each connection of the download, or reading
			// a local file. A large download is kept until decrypted, so
			// an interrupted one continues when run again.
			progress := ui.NewDownloadProgress()
			if local {
				progress = ui.NewStageProgress("reading")
				opts.OnDownloadProgress = progress.Pre.Set
			} else {
				opts.DownloadStatus = &progress.Transfer
				opts.ResumeDir = pending.DownloadsDir()
			}
			// Then each pass that verifies and decrypts it.
			decryptProgress := ui.NewStageProgress("decrypting")
			opts.OnDecryptProgress = func(stage secrets.DecryptStage, done, total int64) {
				decryptProgress.Pre.SetStage(string(stage), done, total)
			}

			var opened *secrets.OpenedSecret
			var written *secrets.WriteResult
			var decrypted *secrets.DecryptedPayload
			defer func() {
				if opened != nil {
					_ = opened.Close() // removes the private temporary ciphertext once the command is done; the plaintext was already written or failed.
				}
			}()

			// The download, or the read of a local file, shows from the
			// moment the SDK says it began: after the key pair is unlocked,
			// so a security key's prompt for a PIN or a touch is not part
			// of it.
			arriving := ui.NewPhaseStart()
			opts.OnPhase = func(p transfer.Phase) {
				if p == transfer.PhaseDownloading || p == transfer.PhaseReading {
					arriving.Mark()
				}
			}
			openLabel, openDone := "Downloading", "Download complete"
			if local {
				openLabel, openDone = "Reading "+filepath.Base(localPath), "File read"
			}
			steps := []ui.Step{
				{
					Label:  openLabel,
					Done:   openDone,
					Live:   progress,
					Begins: arriving,
					Action: func() (string, error) {
						var err error
						if local {
							opened, err = c.Secrets.OpenLocalFile(cmd.Context(), localPath, opts)
						} else {
							opened, err = c.Secrets.Open(cmd.Context(), secretID, opts)
						}
						if err != nil {
							return "", err
						}
						detail := "size=" + ui.FormatBytes(opened.Result.EncryptedSize)
						if kept := opened.Result.ResumedBytes; kept > 0 {
							detail += ", resumed=" + ui.FormatBytes(kept)
						}
						return detail, nil
					},
				},
				{
					Label: "Verifying and decrypting",
					Done:  "Decryption complete",
					Live:  decryptProgress,
					Action: func() (string, error) {
						if opened.Result.PayloadType != "files" {
							var err error
							decrypted, err = opened.Payload(cmd.Context())
							if err != nil {
								return "", err
							}
							return "type=" + opened.Result.PayloadType, nil
						}
						var err error
						if outputDir, err = filesDir(outputDir, opened.Result.RevisionID); err != nil {
							return "", err
						}
						written, err = opened.WriteFiles(cmd.Context(), outputDir, secrets.WriteOptions{Overwrite: forceOverwrite})
						if err != nil {
							return "", err
						}
						if written.Archived {
							return fmt.Sprintf("files=%d", written.Extracted), nil
						}
						return fmt.Sprintf("files=%d", len(written.Files)), nil
					},
				},
			}

			if err := ui.RunPipeline(cmd.Context(), "secret", steps); err != nil {
				var interrupted *secrets.DownloadInterruptedError
				if errors.As(err, &interrupted) {
					return errs.WithDetail(err, downloadResumeDetail(interrupted.Download))
				}
				var stale *trust.StaleRevisionError
				if errors.As(err, &stale) {
					return errs.WithDetail(err, staleRevisionDetail(secretID, stale))
				}
				var unrecorded *trust.UnrecordedSenderError
				if errors.As(err, &unrecorded) {
					return errs.WithDetail(err, recordAccountAdvice(unrecorded.Email, unrecorded.Fingerprint))
				}
				return err
			}
			result := opened.Result

			// ── Summary ──
			fmt.Fprintln(os.Stderr)
			if local {
				ui.KeyValue("File", console.Safe(localPath))
			} else {
				ui.KeyValue("Secret ID", secretID)
			}
			// The name and time the sender signed: the server names the
			// secret too, so these show which secret and which version
			// this is.
			ui.KeyValue("Name", console.Safe(result.SecretName))
			ui.KeyValue("Signed", result.SignedAt.Local().Format("2006-01-02 15:04:05 MST")+" (by the sender's clock)")
			ui.KeyValue("Type", console.Safe(result.PayloadType))
			switch {
			case written != nil && written.Archived:
				ui.KeyValue("Files", fmt.Sprintf("%d (archived)", written.Extracted))
			case written != nil:
				ui.KeyValue("Files", fmt.Sprintf("%d", len(written.Files)))
			}
			// As a send shows them: the files' own bytes, the payload as
			// stored, and what compression did, the sealed payload against
			// the files.
			original := int64(0)
			if written != nil {
				original = written.Size
			}
			if result.Compressed && original > 0 {
				ui.KeyValue("Original Size", ui.FormatBytes(original))
			}
			ui.KeyValue("Size", ui.FormatBytes(result.EncryptedSize)+" encrypted")
			switch {
			case result.Compressed && original > 0:
				ratio := float64(result.PlaintextSize) / float64(original) * 100
				ui.KeyValue("Compression", fmt.Sprintf("%s (%s)", console.Safe(strings.ToUpper(result.Compression)), compressionChange(ratio)))
			case result.Compressed:
				ui.KeyValue("Compression", console.Safe(strings.ToUpper(result.Compression)))
			}
			ui.KeyValue("Sender", senderLine(&result))
			// The recipient list is the one the sender signed; emails are
			// the server's labels for those keys (the sender's, in a local
			// file).
			signedFor := make([]string, len(result.Recipients))
			for i, r := range result.Recipients {
				line := console.Dim + keys.ShortFingerprint(r.Fingerprint) + console.Reset
				if r.Email != "" {
					line = console.Safe(r.Email) + "  " + line
				}
				var notes []string
				if r.Fingerprint == result.RecipientFingerprint {
					notes = append(notes, "you")
				}
				if n := identity.ProtectionName(r.Fingerprint); n != "" {
					notes = append(notes, n)
				}
				if len(notes) > 0 {
					line += " (" + strings.Join(notes, ", ") + ")"
				}
				signedFor[i] = line
			}
			ui.KeyValues("Recipient"+ui.Plural(len(signedFor)), signedFor)
			ui.KeyValue("Protocol", console.Safe(fmt.Sprintf("v%s, %s", result.ProtocolVersion, result.CipherSuite)))
			ui.KeyValue("Payload Digest", result.PayloadDigest[:16]+" (SHA-256, signed by the sender)")
			if written != nil {
				ui.KeyValue("Output", console.Safe(outputDir))
			}
			fmt.Fprintln(os.Stderr)
			if result.SenderFirstUse {
				printFirstUse([]secrets.Recipient{{Email: result.SenderEmail, Fingerprint: result.SenderFingerprint}})
			}
			printOwnKeyNotice(&result)

			if written != nil {
				printWrittenFiles(written, outputDir)
				return nil
			}
			return outputDecrypted(decrypted, outputFile)
		},
	}

	f := cmd.Flags()
	f.BoolVar(&local, "local", false, "The argument is a file written by \"secret encrypt --local\", not a secret ID")
	f.VarP(flags.NewUUID(&revisionID), "revision", "r", "Decrypt this revision `id` instead of the latest")
	flags.SetGroup(f, flags.GroupInput, "local", "revision")

	f.StringVar(&outputDir, "dir", "", "Output `directory` for files (default: ./<revision-id>)")
	f.StringVarP(&outputFile, "output", "o", "", "Output `file` for a message or key-value data (default: stdout)")
	f.BoolVar(&forceOverwrite, "overwrite", false, "Replace existing files at the destination")
	flags.SetGroup(f, flags.GroupOutput, "dir", "output", "overwrite")

	f.VarP(flags.NewFingerprint(&identityFP), "identity", "i", "Decrypt with this local identity (`fingerprint` or a prefix of 16+ characters) instead of picking one")
	f.BoolVar(&useRecoveryCode, "recovery-code", false, "Unlock a security-key protected key pair with its recovery code instead of the security key")
	flags.SetGroup(f, flags.GroupIdentity, "identity", "recovery-code")

	f.Var(flags.NewIntRange(&downloadThreads, 0, 0, transfer.MaxDownloadConcurrency, " (0 adapts to the connection, 1 is one at a time)"), "threads", "Parallel range downloads for large secrets: 0 adapts to the connection, up to 64")
	f.Var(flags.NewMinutes(&presignExpiry, 15, 1, 30), "presign-expiry", "Lifetime of the download's presigned URL before it is renewed: 1m to 30m")
	flags.SetGroup(f, flags.GroupPerformance, "threads", "presign-expiry")

	for _, serverOnly := range []string{"revision", "threads", "presign-expiry"} {
		cmd.MarkFlagsMutuallyExclusive("local", serverOnly)
	}
	return cmd
}

// senderLine is a decrypt's Sender value: the sender the server names, the
// short fingerprint of the key that signed it, and what that key is. A key
// pair on this device is the user's, whoever the server names, so the line
// says so rather than call it the sender's registered key.
func senderLine(r *secrets.DecryptResult) string {
	var notes []string
	switch {
	case r.SenderOwnKey:
		notes = append(notes, "a key on this device")
	case r.SenderEmail != "":
		notes = append(notes, "their registered key")
	}
	if n := identity.ProtectionName(r.SenderFingerprint); n != "" {
		notes = append(notes, n)
	}
	line := keys.ShortFingerprint(r.SenderFingerprint)
	if r.SenderEmail != "" {
		line = console.Safe(r.SenderEmail) + "  " + console.Dim + line + console.Reset
	}
	if len(notes) > 0 {
		line += " (" + strings.Join(notes, ", ") + ")"
	}
	return line
}

// printOwnKeyNotice warns, under a decrypt's result block, when a key pair
// on this device signed the secret but the sender the server names is not
// recorded here as one of the user's accounts. That is either an account of
// the user's this device does not know yet, or the server naming someone
// else as the sender of the user's own secret: nothing here tells them
// apart, so the SDK opens it and the user is told.
func printOwnKeyNotice(r *secrets.DecryptResult) {
	if !r.SenderOwnKey || r.SenderOwnAccount {
		return
	}
	ui.Warning("This secret is signed with a key on this device",
		fmt.Sprintf("It names %[1]s as its sender, but this device has not recorded %[1]s as one of your accounts.\n\n%[2]s\n\n"+
			"If it is not, you signed this secret and it was relabelled as from %[1]s.",
			console.Safe(r.SenderEmail), recordAccountAdvice(r.SenderEmail, r.SenderFingerprint)))
}

// recordAccountAdvice says how to record email, if it is the user's, as one
// of their accounts on this device with fp, the key pair here that signed a
// secret from it: signed in as it, identity sync records it without
// uploading or unlocking anything when fp is registered for it already, and
// otherwise registers fp and makes it the account's primary key.
func recordAccountAdvice(email, fp string) string {
	return fmt.Sprintf("If %s is your account, sign in as it (secret login) and record it as yours on this device with:\n\n"+
		"  secret identity sync -i %s\n\n"+
		"If that key is not registered for it yet, this also registers it and makes it your primary key.", console.Safe(email), console.Safe(fp))
}

// staleRevisionDetail says, for the Error block of a decrypt refused as a
// possible rollback, how to open that older revision on purpose.
func staleRevisionDetail(secretID string, e *trust.StaleRevisionError) string {
	return fmt.Sprintf("The server may be serving an old version of this secret. If %s confirms this older revision is the one you want, open it by id:\n\n"+
		"  secret decrypt %s --revision %s", console.Safe(e.SenderEmail), secretID, console.Safe(e.RevisionID))
}

// filesDir is where a files payload is written: dir (--dir), or
// ./<revision-id>/ so an unintended decrypt never dumps a tree on top of
// the working directory. The revision ID then names a directory, so it
// must be a UUID and never a path.
func filesDir(dir, revisionID string) (string, error) {
	if dir != "" {
		return dir, nil
	}
	id, err := uuid.Parse(revisionID)
	if err != nil || id.String() != revisionID {
		return "", fmt.Errorf("the revision ID %q is not a UUID; pass --dir to choose the output directory", revisionID)
	}
	return "./" + revisionID, nil
}

// checkFilesDestination checks, before the download, that the files of p
// can be written where decrypt writes them (dirFlag is --dir), so a decrypt
// that cannot finish fails without fetching a possibly large payload.
//
// The server lists the files of a revision, except an archive's: a folder
// is sent as one archive, and the server keeps no names from inside it.
// Then only one conflict is foreseeable: the default ./<revision-id>/
// already holding files, which only an earlier decrypt of this revision
// writes there. A --dir the caller chose may well hold other files, so an
// archive's conflicts there show only once it is extracted.
func checkFilesDestination(dirFlag string, p secrets.UpcomingDownload, overwrite bool) error {
	dir, err := filesDir(dirFlag, p.RevisionID)
	if err != nil {
		return err
	}
	if err := secrets.CheckDestination(dir, p.Files, overwrite); err != nil {
		detail := "Nothing was downloaded."
		if !overwrite {
			detail += " Pass --overwrite to replace files that exist, or --dir to write elsewhere."
		}
		return errs.WithDetail(err, detail)
	}
	log := logging.Module(logging.Log, "decrypt")
	if len(p.Files) > 0 {
		log.Debug("destination checked", "dir", dir, "files", len(p.Files), "checked", "each listed file can be written")
		return nil
	}
	if dirFlag == "" && !overwrite && dirHasEntries(dir) {
		return errs.WithDetail(fmt.Errorf("%s is not empty", dir),
			"It holds files, likely from an earlier decrypt of this revision. Nothing was downloaded.\n\n"+
				"Pass --overwrite to replace them, or --dir to write elsewhere.")
	}
	log.Debug("destination checked", "dir", dir, "checked", "the directory can be written",
		"reason", "the server keeps no file names inside an archive, so a name conflict shows once it is extracted")
	return nil
}

// revisionKey is the fingerprint of the key the revision revisionID (the
// latest when it is "") was sealed with for actorID, or "" when the
// revision does not list them.
func revisionKey(detail *secrets.Detail, revisionID, actorID string) string {
	if revisionID == "" {
		revisionID = detail.Secret.LatestRevisionID
	}
	for _, rev := range detail.Revisions {
		if rev.ID != revisionID {
			continue
		}
		for _, r := range rev.Integrity.Recipients {
			if r.ID == actorID {
				return r.KeyFingerprint
			}
		}
		return ""
	}
	return ""
}

// dirHasEntries reports whether dir is a directory holding anything.
func dirHasEntries(dir string) bool {
	f, err := os.Open(dir) // #nosec G304 -- the directory this decrypt writes into.
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }() // read only.
	names, _ := f.Readdirnames(1)
	return len(names) > 0
}

// printWrittenFiles lists what WriteFiles wrote: each file with its size
// and SHA-256, or the archive's entry count.
func printWrittenFiles(w *secrets.WriteResult, outputDir string) {
	if w.Archived {
		ui.Success(fmt.Sprintf("Extracted %d file%s into %s.", w.Extracted, ui.Plural(w.Extracted), outputDir))
		return
	}
	maxName, maxSize := 0, 0
	sizes := make([]string, len(w.Files))
	for i, f := range w.Files {
		sizes[i] = ui.FormatBytes(f.Size)
		maxName = max(maxName, len(console.Safe(f.Path)))
		maxSize = max(maxSize, len(sizes[i]))
	}
	for i, f := range w.Files {
		fmt.Fprintf(os.Stderr, "  %-*s  %s%*s%s  %ssha256:%s%s\n",
			maxName, console.Safe(f.Path),
			console.Dim, maxSize, sizes[i], console.Reset,
			console.Dim, f.SHA256[:16], console.Reset)
	}
	fmt.Fprintln(os.Stderr)
	ui.Success(fmt.Sprintf("Wrote %d file%s into %s.", len(w.Files), ui.Plural(len(w.Files)), outputDir))
}

// outputDecrypted writes a decrypted message or key-value data to stdout,
// or to outputFile.
func outputDecrypted(d *secrets.DecryptedPayload, outputFile string) error {
	switch d.Type {
	case "data":
		var buf strings.Builder
		for _, e := range d.Entries {
			buf.WriteString(e.Key)
			buf.WriteByte('=')
			buf.WriteString(e.Value)
			buf.WriteByte('\n')
		}
		if outputFile != "" {
			if err := safefile.Write(outputFile, []byte(buf.String()), 0600, forceOverwrite); err != nil {
				return err
			}
			ui.Success(fmt.Sprintf("Wrote %d key-value pair%s to %s.", len(d.Entries), ui.Plural(len(d.Entries)), outputFile))
		} else {
			return writeStdout([]byte(buf.String()))
		}

	case "message":
		if outputFile != "" {
			if err := safefile.Write(outputFile, []byte(d.Message), 0600, forceOverwrite); err != nil {
				return err
			}
			ui.Success(fmt.Sprintf("Wrote the message to %s (%s).", outputFile, ui.FormatBytes(int64(len(d.Message)))))
		} else {
			return writeStdout([]byte(d.Message))
		}

	default:
		// Raw fallback
		if outputFile != "" {
			if err := safefile.Write(outputFile, d.Raw, 0600, forceOverwrite); err != nil {
				return err
			}
			ui.Success(fmt.Sprintf("Wrote the content to %s (%s).", outputFile, ui.FormatBytes(int64(len(d.Raw)))))
		} else {
			return writeStdout(d.Raw)
		}
	}
	return nil
}

// writeStdout prints decrypted content. On a terminal, control characters
// other than newline and tab are shown escaped, like \x1b, so content from
// the sender cannot send the terminal commands or rewrite what is on
// screen; a warning says so. Redirected to a file or a pipe, the bytes are
// written as they are. A failed write is returned, so a decrypt redirected
// to a full disk fails instead of reporting success with part of the
// secret.
func writeStdout(b []byte) error {
	if !console.StdoutIsTerminal {
		if _, err := os.Stdout.Write(b); err != nil {
			return fmt.Errorf("could not write to stdout: %w", err)
		}
		return nil
	}
	out, escaped := console.EscapeControls(b)
	if _, err := os.Stdout.Write(out); err != nil {
		return fmt.Errorf("could not write to stdout: %w", err)
	}
	if escaped > 0 {
		ui.Warning(fmt.Sprintf("%d control character%s shown escaped", escaped, ui.Plural(escaped)),
			"The content holds characters that would act on the terminal, so they are shown as escapes like \\x1b. To get the exact bytes, write it to a file with -o, or pipe it.")
	}
	return nil
}
