// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	sdk "github.com/deepsecret-io/sdk"
	"github.com/deepsecret-io/sdk/archive"
	"github.com/deepsecret-io/sdk/compress"
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

// safeRelPath returns a path that is guaranteed to be inside base after
// filepath.Clean. Rejects absolute paths, paths that escape via "..", paths
// containing NUL bytes, and (on every OS) paths containing backslash since
// payloads should never carry Windows separators.
func safeRelPath(base, name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("empty file name")
	}
	if strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("file name contains NUL byte")
	}
	if strings.ContainsRune(name, '\\') {
		return "", fmt.Errorf("file name contains backslash: %q", name)
	}
	cleaned := filepath.Clean(name)
	if filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("absolute file path rejected: %q", name)
	}
	dest := filepath.Join(base, cleaned)
	rel, err := filepath.Rel(base, dest)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("file path escapes output dir: %q", name)
	}
	return dest, nil
}

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

			var result *sdk.DecryptResult

			steps := []step{
				{
					label:    "Downloading and decrypting",
					transfer: downloadProgress,
					action: func() (string, error) {
						downloadProgress.startedAt = time.Now()
						var err error
						result, err = c.DecryptSecretFull(secretID, opts)
						if err != nil {
							dbgErr("decrypt", err)
							return "", err
						}
						return fmt.Sprintf("type=%s, size=%s", result.PayloadType, formatBytes(result.EncryptedSize)), nil
					},
				},
			}

			if err := runPipeline("Decrypt", steps, nil); err != nil {
				return err
			}

			// ── Summary ──
			fmt.Fprintln(os.Stderr)
			printKeyValue("Secret ID", secretID)
			printKeyValue("Type", result.PayloadType)
			fileCount := len(result.Decrypted.Files)
			if fileCount > 0 {
				printKeyValue("Files", fmt.Sprintf("%d", fileCount))
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
			fmt.Fprintln(os.Stderr)

			// Resolve the default output directory only when the payload is
			// actually files. Messages, key-value data, and raw payloads go
			// to stdout (or -o), so creating ./<revision-id>/ for those
			// would just leave empty directories behind. Files default to
			// ./<revision-id>/ so an unintended decrypt never dumps a tree
			// on top of the caller's CWD.
			hasFiles := len(result.Decrypted.Files) > 0
			if outputDir == "" && hasFiles {
				if result.RevisionID == "" {
					return fmt.Errorf("internal error: SDK returned empty RevisionID")
				}
				outputDir = "./" + result.RevisionID
				if err := os.MkdirAll(outputDir, 0755); err != nil {
					return fmt.Errorf("create default output directory %q: %w", outputDir, err)
				}
				printKeyValue("Output", outputDir)
			}

			return outputDecrypted(result, outputDir, outputFile)
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

// outputDecrypted handles writing decrypted content to disk or stdout.
func outputDecrypted(result *sdk.DecryptResult, outputDir, outputFile string) error {
	d := result.Decrypted

	switch d.Type {
	case "files":
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return fmt.Errorf("create output dir: %w", err)
		}

		// Archived payloads (single tar+zstd blob) are stream-extracted to
		// disk so arbitrarily large archives work without buffering every
		// entry into RAM. The CLI is a deliberate, user-driven tool, so the
		// default in-memory limits (2 GB) are too tight; we use generous
		// caps that still protect against pathological input.
		if d.Archived && len(d.Files) == 1 {
			f := d.Files[0]
			if f.SHA256 != "" {
				h := sha256.Sum256(f.Data)
				if actual := hex.EncodeToString(h[:]); actual != f.SHA256 {
					return fmt.Errorf("integrity check failed for %s: expected sha256 %s, got %s", f.Name, f.SHA256, actual)
				}
			}
			lim := &archive.Limits{
				MaxEntries:     100_000,
				MaxEntrySize:   50 << 30,  // 50 GiB per file
				MaxTotalSize:   500 << 30, // 500 GiB total
				AllowOverwrite: forceOverwrite,
			}
			count, err := archive.ExtractTar(f.Data, outputDir, compress.Algorithm(d.ArchiveCompression), lim)
			if err != nil {
				return fmt.Errorf("extract %s: %w", f.Name, err)
			}
			fmt.Fprintf(os.Stderr, "  %s✓%s extracted %d file%s into %s\n",
				ansiGreen, ansiReset, count, plural(count), outputDir)
			return nil
		}

		// Pre-compute column widths for aligned output
		type fileOut struct {
			dest string
			size string
			sha  string
		}
		outputs := make([]fileOut, 0, len(d.Files))
		maxName, maxSize := 0, 0

		for _, f := range d.Files {
			dest, err := safeRelPath(outputDir, f.Name)
			if err != nil {
				return err
			}

			if f.SHA256 != "" {
				h := sha256.Sum256(f.Data)
				actual := hex.EncodeToString(h[:])
				if actual != f.SHA256 {
					return fmt.Errorf("integrity check failed for %s: expected sha256 %s, got %s", f.Name, f.SHA256, actual)
				}
			}
			if f.Size > 0 && int64(len(f.Data)) != f.Size {
				return fmt.Errorf("integrity check failed for %s: expected %d bytes, got %d", f.Name, f.Size, len(f.Data))
			}

			if dir := filepath.Dir(dest); dir != outputDir {
				if err := os.MkdirAll(dir, 0755); err != nil {
					return fmt.Errorf("create directory %s: %w", dir, err)
				}
			}
			// Preserve the sender's permission bits, masked to 0o777 so
			// setuid/setgid/sticky from the payload can't leak onto disk.
			// Fall back to 0600 for legacy revisions that stored no mode.
			mode := f.Mode & 0o777
			if mode == 0 {
				mode = 0600
			}
			dbg("write", "%s mode=%o", f.Name, uint32(mode))
			if err := safeWriteFile(dest, f.Data, mode, forceOverwrite); err != nil {
				return err
			}

			sha := f.SHA256
			if sha == "" {
				h := sha256.Sum256(f.Data)
				sha = hex.EncodeToString(h[:])
			}

			sizeStr := formatBytes(int64(len(f.Data)))
			outputs = append(outputs, fileOut{dest: dest, size: sizeStr, sha: sha[:16]})
			if len(dest) > maxName {
				maxName = len(dest)
			}
			if len(sizeStr) > maxSize {
				maxSize = len(sizeStr)
			}
		}

		for _, o := range outputs {
			fmt.Fprintf(os.Stderr, "  %s✓%s %-*s  %s%*s%s  %ssha256:%s%s\n",
				ansiGreen, ansiReset,
				maxName, o.dest,
				ansiDim, maxSize, o.size, ansiReset,
				ansiDim, o.sha, ansiReset)
		}

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
