// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	sdk "github.com/deepsecret-io/sdk"
	"github.com/deepsecret-io/sdk/api"
	"github.com/deepsecret-io/sdk/crypto"
)

// plural returns "s" when n != 1.
func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// forceOverwrite is wired from the --overwrite flag in newDecryptCmd. When false,
// existing destination files cause writes to fail (O_EXCL); when true, they
// are replaced by a new file renamed over them (safeWriteFile). On Unix, a
// symlink at a created file's leaf is rejected (O_NOFOLLOW), so an attacker
// who can plant one in outputDir cannot redirect plaintext writes; see
// decrypt_unix.go / decrypt_windows.go for the platform-specific
// createExclusive.
var forceOverwrite bool

// safeWriteFile writes decrypted data to dest, created with mode (the umask
// applies) by the platform's createExclusive. Without force it refuses a
// dest that exists. With force it writes a new file beside dest and renames
// it over dest once complete, so dest gets mode instead of keeping an old
// file's, a link at dest is replaced rather than written through, and a
// reader never sees half a file.
func safeWriteFile(dest string, data []byte, mode os.FileMode, force bool) error {
	if !force {
		f, err := createExclusive(dest, mode)
		if err != nil {
			if os.IsExist(err) {
				return withDetail(fmt.Errorf("%s already exists", dest), "Pass --overwrite to replace it.")
			}
			return fmt.Errorf("could not create %s: %w", dest, pathCause(err))
		}
		return writeAndClose(f, dest, data)
	}
	tmp := filepath.Join(filepath.Dir(dest), ".deepsecret-"+rand.Text()+".partial")
	f, err := createExclusive(tmp, mode)
	if err != nil {
		return fmt.Errorf("could not create %s: %w", tmp, pathCause(err))
	}
	if err := writeAndClose(f, tmp, data); err != nil {
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		if rmErr := os.Remove(tmp); rmErr != nil {
			return withDetail(fmt.Errorf("could not replace %s: %w", dest, pathCause(err)),
				fmt.Sprintf("The decrypted content is left in %s, which could not be removed (%v). Delete it.", tmp, pathCause(rmErr)))
		}
		return fmt.Errorf("could not replace %s: %w", dest, pathCause(err))
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
		return withDetail(fmt.Errorf("could not write %s: %w", dest, pathCause(err)),
			fmt.Sprintf("The partly written file could not be removed (%v). Delete it.", pathCause(rmErr)))
	}
	return fmt.Errorf("could not write %s: %w", dest, pathCause(err))
}

func newDecryptCmd() *cobra.Command {
	var (
		outputDir       string
		outputFile      string
		revisionID      string
		identityFP      string
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
			return checkIDs(args, "secret ID")
		},
		RunE: func(_ *cobra.Command, args []string) error {
			secretID, localPath := args[0], ""
			if local {
				secretID, localPath = "", args[0]
				info, err := os.Stat(localPath)
				if err != nil {
					return fmt.Errorf("could not read %s: %w", localPath, pathCause(err))
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
					if err := os.MkdirAll(outputDir, 0o700); err != nil {
						return fmt.Errorf("could not create the output directory %s: %w", outputDir, pathCause(err))
					}
				} else if !info.IsDir() {
					return fmt.Errorf("--dir %s is not a directory", outputDir)
				}
			}
			if outputFile != "" {
				if err := checkOutputFile("output", outputFile); err != nil {
					return err
				}
			}

			c, err := newAuthenticatedClient()
			if err != nil {
				return err
			}

			// Without --identity, pick the key the target revision (or the
			// file) was sealed with for the caller: the user may have
			// changed their primary key, and still hold the older keys that
			// older revisions were sealed for. Otherwise the primary key
			// opens it.
			idLog := api.Module(logger, "identity")
			identitySource := "primary"
			switch {
			case identityFP != "":
				identitySource = "--identity"
			case local:
				rs, err := sdk.LocalFileRecipients(localPath)
				if err != nil {
					// Opening the file reports what is wrong with it.
					idLog.Debug("key selection skipped", "reason", "the file's recipients could not be read", "error", err)
				}
				for _, r := range rs {
					if matched := findLocalKeyByFingerprint(r.Fingerprint); matched != "" {
						identityFP, identitySource = matched, "sealed for"
						break
					}
				}
			default:
				detail, err := c.DescribeSecretFull(secretID)
				if err != nil {
					return secretError(err, secretID)
				}
				actorID, err := c.ResolveActorID()
				if err != nil {
					idLog.Warn("key selection skipped", "reason", "your account ID could not be fetched", "error", err)
					break
				}
				expected := revisionKey(detail, revisionID, actorID)
				switch matched := findLocalKeyByFingerprint(expected); {
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
					"threads", threadCountLabel(downloadThreads), "presign_expiry", time.Duration(presignExpiry)*time.Minute)
			}
			if outputDir != "" {
				settings = append(settings, "dir", outputDir)
			}
			if outputFile != "" {
				settings = append(settings, "output", outputFile)
			}
			api.Module(logger, "decrypt").Debug("options", settings...)

			// Prompt for key password if identity is encrypted
			var keyPassword string
			if identityFP != "" {
				// Explicit or auto-selected identity: check if it's encrypted
				resolved := resolveKeystoreFingerprint(identityFP)
				if isKeyPairEncrypted(resolved) {
					pw, perr := readPassword(fmt.Sprintf("Password for key pair %s: ", crypto.ShortFingerprint(resolved)))
					if perr != nil {
						return perr
					}
					keyPassword = pw
				}
			} else {
				// Primary identity: check if it's encrypted
				if _, _, err := c.LoadPrimaryIdentity(""); err != nil {
					if strings.Contains(err.Error(), "password-encrypted") {
						pw, perr := readPassword("Password for your primary key: ")
						if perr != nil {
							return perr
						}
						keyPassword = pw
						if _, _, err := c.LoadPrimaryIdentity(keyPassword); err != nil {
							return fmt.Errorf("could not unlock your primary key: %w", err)
						}
					} else {
						return fmt.Errorf("could not load your primary key: %w", err)
					}
				}
			}

			// Build SDK options
			opts := sdk.DecryptOptions{
				Revision:             revisionID,
				Identity:             identityFP,
				Password:             keyPassword,
				DownloadThreads:      downloadThreads,
				PresignExpiryMinutes: presignExpiry,
				Logger:               logger,
				// The download can be large: check that the files can be
				// written before fetching them.
				BeforeDownload: func(p sdk.UpcomingDownload) error {
					if p.PayloadType != "files" {
						return nil
					}
					return checkFilesDestination(outputDir, p, forceOverwrite)
				},
			}

			// Live progress: each connection of the download, or reading
			// a local file. A large download is kept until decrypted, so
			// an interrupted one continues when run again.
			progress := newDownloadProgress()
			if local {
				progress = newStageProgress("reading")
				opts.OnDownloadProgress = progress.pre.set
			} else {
				opts.DownloadStatus = &progress.transfer
				opts.ResumeDir = downloadsDir()
			}
			// Then each pass that verifies and decrypts it.
			decryptProgress := newStageProgress("decrypting")
			opts.OnDecryptProgress = func(stage sdk.DecryptStage, done, total int64) {
				decryptProgress.pre.setStage(string(stage), done, total)
			}

			var opened *sdk.OpenedSecret
			var written *sdk.WriteResult
			var decrypted *sdk.DecryptedPayload
			defer func() {
				if opened != nil {
					_ = opened.Close() // removes the private temporary ciphertext once the command is done; the plaintext was already written or failed.
				}
			}()

			openLabel, openDone := "Downloading", "Download complete"
			if local {
				openLabel, openDone = "Checking the sender and reading "+filepath.Base(localPath), "File read"
			}
			steps := []step{
				{
					label: openLabel,
					done:  openDone,
					live:  progress,
					action: func() (string, error) {
						var err error
						if local {
							opened, err = c.OpenLocalFile(localPath, opts)
						} else {
							opened, err = c.OpenSecret(secretID, opts)
						}
						if err != nil {
							return "", err
						}
						detail := "size=" + formatBytes(opened.Result.EncryptedSize)
						if kept := opened.Result.ResumedBytes; kept > 0 {
							detail += ", resumed=" + formatBytes(kept)
						}
						return detail, nil
					},
				},
				{
					label: "Verifying and decrypting",
					done:  "Decryption complete",
					live:  decryptProgress,
					action: func() (string, error) {
						if opened.Result.PayloadType != "files" {
							var err error
							decrypted, err = opened.Payload()
							if err != nil {
								return "", err
							}
							return "type=" + opened.Result.PayloadType, nil
						}
						var err error
						if outputDir, err = filesDir(outputDir, opened.Result.RevisionID); err != nil {
							return "", err
						}
						written, err = opened.WriteFiles(outputDir, sdk.WriteOptions{Overwrite: forceOverwrite})
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

			if err := runPipeline("secret", steps); err != nil {
				var interrupted *sdk.DownloadInterruptedError
				if errors.As(err, &interrupted) {
					return withDetail(err, downloadResumeDetail(interrupted.Download))
				}
				return err
			}
			result := opened.Result

			// ── Summary ──
			fmt.Fprintln(os.Stderr)
			if local {
				printKeyValue("File", safe(localPath))
			} else {
				printKeyValue("Secret ID", secretID)
			}
			printKeyValue("Type", safe(result.PayloadType))
			switch {
			case written != nil && written.Archived:
				printKeyValue("Files", fmt.Sprintf("%d (archived)", written.Extracted))
			case written != nil:
				printKeyValue("Files", fmt.Sprintf("%d", len(written.Files)))
			}
			printKeyValue("Size", formatBytes(result.EncryptedSize)+" encrypted")
			if result.Compressed {
				printKeyValue("Compression", safe(strings.ToUpper(result.Compression)))
			}
			if result.SenderEmail != "" {
				printKeyValue("Sender", fmt.Sprintf("%s  %s%s%s (their registered key)", safe(result.SenderEmail),
					ansiDim, crypto.ShortFingerprint(result.SenderFingerprint), ansiReset))
			} else {
				printKeyValue("Sender", crypto.ShortFingerprint(result.SenderFingerprint))
			}
			// The recipient list is the one the sender signed; emails are
			// the server's labels for those keys (the sender's, in a local
			// file).
			signedFor := make([]string, len(result.Recipients))
			for i, r := range result.Recipients {
				line := ansiDim + crypto.ShortFingerprint(r.Fingerprint) + ansiReset
				if r.Email != "" {
					line = safe(r.Email) + "  " + line
				}
				if r.Fingerprint == result.RecipientFingerprint {
					line += " (you)"
				}
				signedFor[i] = line
			}
			printKeyValues("Recipient"+plural(len(signedFor)), signedFor)
			printKeyValue("Protocol", safe(fmt.Sprintf("v%s, %s", result.ProtocolVersion, result.CipherSuite)))
			printKeyValue("Payload Digest", result.PayloadDigest[:16]+" (SHA-256, signed by the sender)")
			if written != nil {
				printKeyValue("Output", safe(outputDir))
			}
			fmt.Fprintln(os.Stderr)
			if result.SenderFirstUse {
				printFirstUse([]sdk.Recipient{{Email: result.SenderEmail, Fingerprint: result.SenderFingerprint}})
			}

			if written != nil {
				printWrittenFiles(written, outputDir)
				return nil
			}
			return outputDecrypted(decrypted, outputFile)
		},
	}

	f := cmd.Flags()
	f.BoolVar(&local, "local", false, "The argument is a file written by \"secret encrypt --local\", not a secret ID")
	f.VarP(&uuidFlag{&revisionID}, "revision", "r", "Decrypt this revision `id` instead of the latest")
	setGroup(f, groupInput, "local", "revision")

	f.StringVar(&outputDir, "dir", "", "Output `directory` for files (default: ./<revision-id>)")
	f.StringVarP(&outputFile, "output", "o", "", "Output `file` for a message or key-value data (default: stdout)")
	f.BoolVar(&forceOverwrite, "overwrite", false, "Replace existing files at the destination")
	setGroup(f, groupOutput, "dir", "output", "overwrite")

	f.VarP(&fingerprintFlag{&identityFP}, "identity", "i", "Decrypt with this local identity (`fingerprint` or a prefix of 16+ characters) instead of picking one")
	setGroup(f, groupIdentity, "identity")

	f.Var(newIntRange(&downloadThreads, 0, 0, api.MaxDownloadConcurrency, " (0 adapts to the connection, 1 is one at a time)"), "threads", "Parallel range downloads for large secrets: 0 adapts to the connection, up to 64")
	f.Var(newMinutes(&presignExpiry, 15, 1, 30), "presign-expiry", "Lifetime of the download's presigned URL before it is renewed: 1m to 30m")
	setGroup(f, groupPerformance, "threads", "presign-expiry")

	for _, serverOnly := range []string{"revision", "threads", "presign-expiry"} {
		cmd.MarkFlagsMutuallyExclusive("local", serverOnly)
	}
	return cmd
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
func checkFilesDestination(dirFlag string, p sdk.UpcomingDownload, overwrite bool) error {
	dir, err := filesDir(dirFlag, p.RevisionID)
	if err != nil {
		return err
	}
	if err := sdk.CheckDestination(dir, p.Files, overwrite); err != nil {
		detail := "Nothing was downloaded."
		if !overwrite {
			detail += " Pass --overwrite to replace files that exist, or --dir to write elsewhere."
		}
		return withDetail(err, detail)
	}
	log := api.Module(logger, "decrypt")
	if len(p.Files) > 0 {
		log.Debug("destination checked", "dir", dir, "files", len(p.Files), "checked", "each listed file can be written")
		return nil
	}
	if dirFlag == "" && !overwrite && dirHasEntries(dir) {
		return withDetail(fmt.Errorf("%s is not empty", dir),
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
func revisionKey(detail *sdk.SecretDetail, revisionID, actorID string) string {
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
func printWrittenFiles(w *sdk.WriteResult, outputDir string) {
	if w.Archived {
		printSuccess(fmt.Sprintf("Extracted %d file%s into %s.", w.Extracted, plural(w.Extracted), outputDir))
		return
	}
	maxName, maxSize := 0, 0
	sizes := make([]string, len(w.Files))
	for i, f := range w.Files {
		sizes[i] = formatBytes(f.Size)
		maxName = max(maxName, len(safe(f.Path)))
		maxSize = max(maxSize, len(sizes[i]))
	}
	for i, f := range w.Files {
		fmt.Fprintf(os.Stderr, "  %-*s  %s%*s%s  %ssha256:%s%s\n",
			maxName, safe(f.Path),
			ansiDim, maxSize, sizes[i], ansiReset,
			ansiDim, f.SHA256[:16], ansiReset)
	}
	fmt.Fprintln(os.Stderr)
	printSuccess(fmt.Sprintf("Wrote %d file%s into %s.", len(w.Files), plural(len(w.Files)), outputDir))
}

// outputDecrypted writes a decrypted message or key-value data to stdout,
// or to outputFile.
func outputDecrypted(d *sdk.DecryptedPayload, outputFile string) error {
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
			if err := safeWriteFile(outputFile, []byte(buf.String()), 0600, forceOverwrite); err != nil {
				return err
			}
			printSuccess(fmt.Sprintf("Wrote %d key-value pair%s to %s.", len(d.Entries), plural(len(d.Entries)), outputFile))
		} else {
			return writeStdout([]byte(buf.String()))
		}

	case "message":
		if outputFile != "" {
			if err := safeWriteFile(outputFile, []byte(d.Message), 0600, forceOverwrite); err != nil {
				return err
			}
			printSuccess(fmt.Sprintf("Wrote the message to %s (%s).", outputFile, formatBytes(int64(len(d.Message)))))
		} else {
			return writeStdout([]byte(d.Message))
		}

	default:
		// Raw fallback
		if outputFile != "" {
			if err := safeWriteFile(outputFile, d.Raw, 0600, forceOverwrite); err != nil {
				return err
			}
			printSuccess(fmt.Sprintf("Wrote the content to %s (%s).", outputFile, formatBytes(int64(len(d.Raw)))))
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
	if !stdoutIsTerminal {
		if _, err := os.Stdout.Write(b); err != nil {
			return fmt.Errorf("could not write to stdout: %w", err)
		}
		return nil
	}
	out, escaped := escapeControls(b)
	if _, err := os.Stdout.Write(out); err != nil {
		return fmt.Errorf("could not write to stdout: %w", err)
	}
	if escaped > 0 {
		printWarning(fmt.Sprintf("%d control character%s shown escaped", escaped, plural(escaped)),
			"The content holds characters that would act on the terminal, so they are shown as escapes like \\x1b. To get the exact bytes, write it to a file with -o, or pipe it.")
	}
	return nil
}

// escapeControls writes control characters, invisible formatting marks
// and invalid UTF-8 in b as escapes, keeping newlines and tabs, and counts
// what it escaped.
func escapeControls(b []byte) ([]byte, int) {
	var out []byte
	escaped := 0
	for len(b) > 0 {
		r, n := utf8.DecodeRune(b)
		switch {
		case r == utf8.RuneError && n <= 1:
			out = fmt.Appendf(out, "\\x%02x", b[0])
			escaped++
		case r == '\n' || r == '\t':
			out = append(out, b[:n]...)
		case unicode.IsControl(r) || (unicode.Is(unicode.Cf, r) && r != '\u200d'):
			if r < 0x100 {
				out = fmt.Appendf(out, "\\x%02x", r)
			} else {
				out = fmt.Appendf(out, "\\u%04x", r)
			}
			escaped++
		default:
			out = append(out, b[:n]...)
		}
		b = b[n:]
	}
	return out, escaped
}
