// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	sdk "github.com/deepsecret-io/sdk"
	"github.com/deepsecret-io/sdk/crypto"
)

// plural returns "s" when n != 1.
func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// forceOverwrite is wired from the --force flag in newDecryptCmd. When false,
// existing destination files cause writes to fail (O_EXCL); when true, they
// are truncated. On Unix, symlinks at the destination leaf are also rejected
// (O_NOFOLLOW) so an attacker who can plant a symlink in outputDir cannot
// redirect plaintext writes; see decrypt_unix.go / decrypt_windows.go for the
// platform-specific safeWriteFile.
var forceOverwrite bool

func newDecryptCmd() *cobra.Command {
	var (
		outputDir       string
		outputFile      string
		revisionID      string
		identityFP      string
		downloadThreads int
		presignExpiry   int
	)

	cmd := &cobra.Command{
		Use:     "decrypt [secret-id]",
		Aliases: []string{"dec"},
		Short:   "Decrypt a secret (alias: dec)",
		Long: `Decrypt a secret. Smart output based on content type:
  - File secrets: written to a directory named after the revision UUID by
    default, so an unintended decrypt never clobbers files in the current
    directory. Pass -d to override.
  - Key-value secrets: printed to stdout (or to -o <file>).

Examples:
  secret decrypt abc123-...                       # writes to ./<revision-id>/
  secret decrypt abc123-... -d ./out              # writes to ./out
  secret decrypt abc123-... --revision rev-id-...`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("provide a secret ID as argument")
			}

			secretID := args[0]
			dbg("setup", "secret_id=%s", secretID)
			if revisionID != "" {
				dbg("setup", "revision=%s", revisionID)
			}
			if outputDir != "" {
				dbg("setup", "output_dir=%s", outputDir)
			}

			// Validate secret ID format early
			if _, err := uuid.Parse(secretID); err != nil {
				return fmt.Errorf("invalid secret ID %q: expected UUID format", secretID)
			}

			if presignExpiry < 1 || presignExpiry > 30 {
				return fmt.Errorf("--presign-expiry must be between 1 and 30 minutes (got %d)", presignExpiry)
			}

			// Validate an explicit -d up front. The empty default is resolved
			// later to the revision UUID once the SDK has fetched the secret;
			// we cannot create that directory now because we don't know the
			// revision ID yet.
			if outputDir != "" {
				if info, err := os.Stat(outputDir); err != nil {
					if err := os.MkdirAll(outputDir, 0755); err != nil {
						return fmt.Errorf("failed to create output directory %q: %w", outputDir, err)
					}
				} else if !info.IsDir() {
					return fmt.Errorf("output path %q is not a directory", outputDir)
				}
			}
			if outputFile != "" {
				dir := filepath.Dir(outputFile)
				if dir != "." && dir != "" {
					if _, err := os.Stat(dir); err != nil {
						return fmt.Errorf("output directory %q for --output does not exist", dir)
					}
				}
			}

			c, err := newAuthenticatedClient()
			if err != nil {
				dbgErr("setup", err)
				return err
			}
			dbg("setup", "authenticated client ready")

			// Auto-select identity from the key the target revision was
			// sealed for, for the caller, when the user did not pass
			// --identity. The user may have rotated their primary identity,
			// but still hold older keys locally that match older revisions.
			identitySource := "primary"
			if identityFP != "" {
				identitySource = "explicit (--identity)"
			} else {
				detail, derr := c.DescribeSecretFull(secretID)
				actorID, aerr := c.ResolveActorID()
				if derr == nil && aerr == nil && len(detail.Revisions) > 0 {
					targetID := revisionID
					if targetID == "" {
						targetID = detail.Secret.LatestRevisionID
					}
					var expectedFP string
					for _, rev := range detail.Revisions {
						if rev.ID != targetID {
							continue
						}
						for _, r := range rev.Integrity.Recipients {
							if r.ID == actorID {
								expectedFP = r.KeyFingerprint
								break
							}
						}
						break
					}
					if expectedFP != "" {
						if matched := findLocalKeyByFingerprint(expectedFP); matched != "" {
							identityFP = matched
							identitySource = "auto-selected from local keystore"
							dbg("identity", "auto-selected key for recipient fingerprint=%s", crypto.ShortFingerprint(expectedFP))
						} else {
							dbg("identity", "no local key matches recipient fingerprint=%s", crypto.ShortFingerprint(expectedFP))
							dbg("identity", "falling back to primary identity")
						}
					}
				}
			}

			// Print resolved configuration once, before any phase logs.
			dbg("config", "presign-expiry=%dm", presignExpiry)
			dbg("config", "download-threads=%s", threadCountLabel(downloadThreads, 4))
			dbg("config", "identity-source=%s", identitySource)
			if identityFP != "" {
				dbg("config", "identity=%s", crypto.ShortFingerprint(identityFP))
			}

			// Prompt for key password if identity is encrypted
			var keyPassword string
			if identityFP != "" {
				// Explicit or auto-selected identity: check if it's encrypted
				resolved := resolveKeystoreFingerprint(identityFP)
				if isKeyPairEncrypted(resolved) {
					pw, perr := readPassword("Enter key password: ")
					if perr != nil {
						return perr
					}
					keyPassword = pw
				}
			} else {
				// Primary identity: check if it's encrypted
				if _, _, err := c.LoadPrimaryIdentity(""); err != nil {
					if strings.Contains(err.Error(), "password-encrypted") {
						pw, perr := readPassword("Enter key password: ")
						if perr != nil {
							return perr
						}
						keyPassword = pw
						if _, _, err := c.LoadPrimaryIdentity(keyPassword); err != nil {
							return fmt.Errorf("failed to unlock identity: %w", err)
						}
					} else {
						return fmt.Errorf("load identity: %w", err)
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
				OnDebug:              func(step, msg string) { dbg(step, "%s", msg) },
			}

			// Download progress callback
			downloadProgress := &transferProgress{}
			opts.OnDownloadProgress = func(transferred, total int64) {
				downloadProgress.transferred.Store(transferred)
				downloadProgress.total = total
			}

			var opened *sdk.OpenedSecret
			var written *sdk.WriteResult
			var decrypted *sdk.DecryptedPayload
			defer func() {
				if opened != nil {
					opened.Close()
				}
			}()

			steps := []step{
				{
					label:    "Downloading",
					transfer: downloadProgress,
					action: func() (string, error) {
						downloadProgress.startedAt = time.Now()
						var err error
						opened, err = c.OpenSecret(secretID, opts)
						if err != nil {
							dbgErr("decrypt", err)
							return "", err
						}
						return fmt.Sprintf("type=%s, size=%s", opened.Result.PayloadType, formatBytes(opened.Result.EncryptedSize)), nil
					},
				},
				{
					label: "Verifying and decrypting",
					action: func() (string, error) {
						if opened.Result.PayloadType != "files" {
							var err error
							decrypted, err = opened.Payload()
							if err != nil {
								dbgErr("decrypt", err)
								return "", err
							}
							return "verified", nil
						}
						// Files default to ./<revision-id>/ so an unintended
						// decrypt never dumps a tree on top of the caller's CWD.
						if outputDir == "" {
							if opened.Result.RevisionID == "" {
								return "", fmt.Errorf("internal error: SDK returned empty RevisionID")
							}
							outputDir = "./" + opened.Result.RevisionID
						}
						var err error
						written, err = opened.WriteFiles(outputDir, sdk.WriteOptions{Overwrite: forceOverwrite})
						if err != nil {
							dbgErr("decrypt", err)
							return "", err
						}
						if written.Archived {
							return fmt.Sprintf("extracted %d file%s", written.Extracted, plural(written.Extracted)), nil
						}
						return fmt.Sprintf("%d file%s written", len(written.Files), plural(len(written.Files))), nil
					},
				},
			}

			if err := runPipeline("Decrypt", steps, nil); err != nil {
				return err
			}
			result := opened.Result

			// ── Summary ──
			fmt.Fprintln(os.Stderr)
			printKeyValue("Secret ID", secretID)
			printKeyValue("Type", result.PayloadType)
			switch {
			case written != nil && written.Archived:
				printKeyValue("Files", fmt.Sprintf("%d (archived)", written.Extracted))
			case written != nil:
				printKeyValue("Files", fmt.Sprintf("%d", len(written.Files)))
			}
			printKeyValue("Size", formatBytes(result.EncryptedSize)+" encrypted")
			if result.Compressed {
				printKeyValue("Compression", strings.ToUpper(result.Compression))
			}
			printKeyValue("Sender", crypto.ShortFingerprint(result.SenderFingerprint))
			// The recipient list is the one the sender signed; emails are
			// the server's labels for those keys.
			signedFor := make([]string, len(result.Recipients))
			for i, r := range result.Recipients {
				line := ansiDim + crypto.ShortFingerprint(r.Fingerprint) + ansiReset
				if r.Email != "" {
					line = r.Email + "  " + line
				}
				if r.Fingerprint == result.RecipientFingerprint {
					line += " (you)"
				}
				signedFor[i] = line
			}
			printKeyValues("Recipient"+plural(len(signedFor)), signedFor)
			printKeyValue("Protocol", fmt.Sprintf("v%s, %s", result.ProtocolVersion, result.CipherSuite))
			printKeyValue("Payload Digest", result.PayloadDigest[:16]+" (SHA-256, signed by the sender)")
			if written != nil {
				printKeyValue("Output", outputDir)
			}
			fmt.Fprintln(os.Stderr)

			if written != nil {
				printWrittenFiles(written, outputDir)
				return nil
			}
			return outputDecrypted(decrypted, outputFile)
		},
	}

	cmd.Flags().StringVarP(&outputDir, "dir", "d", "", "Output directory for file secrets (default: ./<revision-id>)")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write KV output to file instead of stdout")
	cmd.Flags().StringVar(&revisionID, "revision", "", "Decrypt a specific revision ID (default: latest)")
	cmd.Flags().StringVarP(&identityFP, "identity", "i", "", "Use a specific local identity (fingerprint or prefix) instead of primary")
	cmd.Flags().BoolVarP(&forceOverwrite, "force", "f", false, "Overwrite destination files if they exist")
	cmd.Flags().IntVarP(&downloadThreads, "threads", "t", 0, "Parallel byte-range download threads (0=SDK default of 4, 1=disable parallelism, max=64). Larger files benefit from more threads on high-RTT or high-bandwidth links.")
	cmd.Flags().IntVar(&presignExpiry, "presign-expiry", 15, "Presigned download URL lifetime in minutes (allowed: 1-30, default: 15)")

	return cmd
}

// printWrittenFiles lists what WriteFiles wrote: each file with its size
// and SHA-256, or the archive's entry count.
func printWrittenFiles(w *sdk.WriteResult, outputDir string) {
	if w.Archived {
		fmt.Fprintf(os.Stderr, "  %s✓%s extracted %d file%s into %s\n",
			ansiGreen, ansiReset, w.Extracted, plural(w.Extracted), outputDir)
		return
	}
	maxName, maxSize := 0, 0
	sizes := make([]string, len(w.Files))
	for i, f := range w.Files {
		sizes[i] = formatBytes(f.Size)
		maxName = max(maxName, len(f.Path))
		maxSize = max(maxSize, len(sizes[i]))
	}
	for i, f := range w.Files {
		fmt.Fprintf(os.Stderr, "  %s✓%s %-*s  %s%*s%s  %ssha256:%s%s\n",
			ansiGreen, ansiReset,
			maxName, f.Path,
			ansiDim, maxSize, sizes[i], ansiReset,
			ansiDim, f.SHA256[:16], ansiReset)
	}
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
			printSuccess(fmt.Sprintf("Decrypted %d data entries to %s", len(d.Entries), outputFile))
		} else {
			fmt.Print(buf.String())
		}

	case "message":
		if outputFile != "" {
			if err := safeWriteFile(outputFile, []byte(d.Message), 0600, forceOverwrite); err != nil {
				return err
			}
			printSuccess(fmt.Sprintf("Decrypted message to %s (%s)", outputFile, formatBytes(int64(len(d.Message)))))
		} else {
			fmt.Print(d.Message)
		}

	default:
		// Raw fallback
		if outputFile != "" {
			if err := safeWriteFile(outputFile, d.Raw, 0600, forceOverwrite); err != nil {
				return err
			}
			printSuccess(fmt.Sprintf("Decrypted to %s (%d bytes)", outputFile, len(d.Raw)))
		} else {
			os.Stdout.Write(d.Raw)
		}
	}
	return nil
}
