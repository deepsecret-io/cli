// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"github.com/deepsecret-io/sdk"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func newEncryptCmd() *cobra.Command {
	var (
		recipientEmail string
		groupName      string
		name           string
		inputFiles     []string
		dataPairs      []string
		ttl            string
		allowedIPs     []string
		skipHidden     bool
		forceArchive   bool
		identityFP     string
		uploadThreads  int
		presignExpiry  int
	)

	cmd := &cobra.Command{
		Use:     "encrypt [files...]",
		Aliases: []string{"enc"},
		Short:   "Encrypt and send a secret (alias: enc)",
		Long: `Encrypt files, directories, or key-value pairs for a recipient using hybrid
post-quantum encryption (X25519 + ML-KEM-768 + AES-256-GCM).

Files and directories can be passed as positional args or with -f flags.
Directories are recursively included with their structure preserved.

Policies:
  --ttl  Time-to-live (e.g. "24h", "7d", "30m"). Secret expires after this duration.
  --ip   Restrict access to specific IPs or CIDRs (can be repeated).

Privacy:
  --archive, --hide-metadata
      Bundle all files into a single tar.zst archive before encrypting.
      The server only sees one opaque blob — individual file names, sizes,
      and directory structure are never sent as metadata. Use this when
      file metadata itself is sensitive.

Examples:
  secret encrypt config.yaml -t alice@example.com
  secret encrypt auth.service keys.service traefik -t alice@example.com
  secret encrypt -f config.yaml                        # send to self
  secret encrypt -d DB_PASS=secret -d API_KEY=abc -t alice@example.com
  secret encrypt -f key.pem -t alice@example.com --ttl 24h
  secret encrypt -f db.env -t alice@example.com --ip 10.0.0.0/8
  secret encrypt -f . --hide-metadata -t alice@example.com  # hide file metadata from server
  secret encrypt -f db.env -g engineering              # send to all members of "engineering" group`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Merge positional args into inputFiles
			inputFiles = append(inputFiles, args...)

			// Debug: stat each input file
			if debug && len(inputFiles) > 0 {
				logDebug("input", "files=%d data_pairs=%d", len(inputFiles), len(dataPairs))
				for _, f := range inputFiles {
					info, err := os.Stat(f)
					if err != nil {
						logDebug("input", "%s: stat error: %s", f, err)
						continue
					}
					if info.IsDir() {
						logDebug("input", "%s: dir", f)
					} else {
						logDebug("input", "%s: file size=%s", f, formatBytes(info.Size()))
					}
				}
			}

			if len(inputFiles) > 0 && len(dataPairs) > 0 {
				return fmt.Errorf("use either --file or --data, not both")
			}

			if presignExpiry < 1 || presignExpiry > 30 {
				return fmt.Errorf("--presign-expiry must be between 1 and 30 minutes (got %d)", presignExpiry)
			}

			if recipientEmail != "" && groupName != "" {
				return fmt.Errorf("use either --to or --group, not both")
			}

			// Validate data pair format early
			for _, kv := range dataPairs {
				if !strings.Contains(kv, "=") {
					return fmt.Errorf("invalid --data format %q (expected KEY=VALUE)", kv)
				}
			}

			// Validate recipient email format early (basic sanity)
			if recipientEmail != "" {
				if !strings.Contains(recipientEmail, "@") || !strings.Contains(recipientEmail, ".") {
					return fmt.Errorf("invalid recipient email %q", recipientEmail)
				}
			}

			// Read stdin early if no -f or -d (before network calls, needs raw terminal)
			var stdinData []byte
			if len(inputFiles) == 0 && len(dataPairs) == 0 {
				stat, _ := os.Stdin.Stat()
				if stat.Mode()&os.ModeCharDevice != 0 {
					fmt.Fprintln(os.Stderr, "Reading from stdin (paste text, then press Ctrl+D to finish):")
				}
				var err error
				stdinData, err = io.ReadAll(os.Stdin)
				if err != nil {
					return fmt.Errorf("read stdin: %w", err)
				}
				if len(bytes.TrimSpace(stdinData)) == 0 {
					return fmt.Errorf("empty input: provide --file, --data, or pipe/paste content via stdin")
				}
			}

			c, err := newAuthenticatedClient()
			if err != nil {
				dbgErr("encrypt", err)
				return err
			}
			// "client ready" was redundant noise — the next line is the real action.

			// Resolve the recipient list. Sources (in priority order):
			//   1. -g/--group  → fetch all group members (excluding self)
			//   2. -t/--to     → single explicit recipient
			//   3. (none)      → send to self
			var recipients []string
			switch {
			case groupName != "":
				info, err := c.WhoAmI()
				if err != nil {
					return fmt.Errorf("fetch account info: %w", err)
				}
				if info.OrgID == "" {
					return fmt.Errorf("--group requires being a member of an organization")
				}
				groups, err := c.ListGroups(info.OrgID)
				if err != nil {
					return fmt.Errorf("list groups: %w", err)
				}
				var matched *sdk.GroupInfo
				wanted := strings.ToLower(groupName)
				for i := range groups {
					if strings.ToLower(groups[i].Name) == wanted {
						matched = &groups[i]
						break
					}
				}
				if matched == nil {
					available := make([]string, 0, len(groups))
					for _, g := range groups {
						available = append(available, g.Name)
					}
					if len(available) == 0 {
						return fmt.Errorf("group %q not found (no groups exist in this organization)", groupName)
					}
					return fmt.Errorf("group %q not found (available: %s)", groupName, strings.Join(available, ", "))
				}
				for _, m := range matched.Members {
					if m.Email == "" {
						continue
					}
					if strings.EqualFold(m.Email, info.Email) {
						continue // exclude self
					}
					recipients = append(recipients, m.Email)
				}
				if len(recipients) == 0 {
					return fmt.Errorf("group %q has no other members to send to.\n  Tip: drop -g/--group to self-send this secret, or add another member to the group first", matched.Name)
				}
				fmt.Fprintf(os.Stderr, "%sds.encrypt:%s %s→%s sending to group %q (%d recipient%s)\n",
					ansiCyan, ansiReset, ansiDim, ansiReset, matched.Name, len(recipients), pluralS(len(recipients)))
			case recipientEmail != "":
				recipients = []string{recipientEmail}
			default:
				info, err := c.WhoAmI()
				if err != nil {
					return fmt.Errorf("fetch account info: %w", err)
				}
				recipients = []string{info.Email}
				fmt.Fprintf(os.Stderr, "%sds.encrypt:%s %s→%s sending to self (%s)\n", ansiCyan, ansiReset, ansiDim, ansiReset, info.Email)
			}

			logDebug("setup", "recipients=%d", len(recipients))
			if name != "" {
				logDebug("setup", "name=%q", name)
			}

			// Normalize list flags: support both repeating (--ip a --ip b) and
			// comma/space-separated (--ip a,b,c) forms, and any mix.
			normalizedIPs := splitListFlag(allowedIPs)

			// Print resolved configuration once, before any phase logs.
			identitySource := "primary"
			if identityFP != "" {
				identitySource = "explicit (--identity)"
			}
			logDebug("config", "presign-expiry=%dm", presignExpiry)
			logDebug("config", "upload-threads=%s", threadCountLabel(uploadThreads, 4))
			logDebug("config", "identity-source=%s", identitySource)

			// Prompt for key password if identity is encrypted
			var keyPassword string
			if identityFP != "" {
				resolved := resolveKeystoreFingerprint(identityFP)
				if isKeyPairEncrypted(resolved) {
					pw, perr := readPassword("Enter key password: ")
					if perr != nil {
						return perr
					}
					keyPassword = pw
				}
			} else {
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
			opts := sdk.EncryptOptions{
				Name:                 name,
				Compress:             sdk.CompressZstd,
				Archive:              forceArchive,
				AutoArchive:          true,
				SkipHidden:           skipHidden,
				TTL:                  ttl,
				IPs:                  normalizedIPs,
				ValidateTier:         true,
				Password:             keyPassword,
				Identity:             identityFP,
				UploadThreads:        uploadThreads,
				PresignExpiryMinutes: presignExpiry,
				OnDebug:              func(step, msg string) { logDebug(step, "%s", msg) },
			}

			// Upload progress callback
			uploadProgress := &transferProgress{}
			opts.OnUploadProgress = func(transferred, total int64) {
				uploadProgress.transferred.Store(transferred)
				uploadProgress.total = total
			}

			// Determine name if not provided
			if opts.Name == "" {
				switch {
				case len(inputFiles) > 0:
					resolved := inputFiles[0]
					if abs, err := filepath.Abs(resolved); err == nil {
						resolved = filepath.Base(abs)
					}
					opts.Name = resolved
					if len(inputFiles) > 1 {
						opts.Name = fmt.Sprintf("%s (%d files)", resolved, len(inputFiles))
					}
				case len(stdinData) > 0:
					opts.Name = fmt.Sprintf("message-%s", time.Now().Format("20060102-150405"))
				default:
					opts.Name = fmt.Sprintf("secret-%s", time.Now().Format("20060102-150405"))
				}
			}

			// Encrypt+upload once per recipient. Each recipient gets a unique
			// ciphertext encrypted to their public key — this is required by the
			// E2E PQC contract; we can't reuse a single ciphertext.
			results := make([]*sdk.EncryptResult, 0, len(recipients))
			var firstErr error
			for i, rcpt := range recipients {
				rcpt := rcpt
				idx := i + 1
				label := "Encrypting and uploading"
				if len(recipients) > 1 {
					label = fmt.Sprintf("Encrypting and uploading [%d/%d] %s", idx, len(recipients), rcpt)
				}
				var result *sdk.EncryptResult
				stepDef := step{
					label:    label,
					transfer: uploadProgress,
					action: func() (string, error) {
						var err error
						switch {
						case len(inputFiles) > 0:
							// (per-recipient line removed — flow is clear from the encrypt phase logs)
							uploadProgress.startedAt = time.Now()
							result, err = c.EncryptPaths(rcpt, inputFiles, opts)
						case len(dataPairs) > 0:
							kvMap := make(map[string]string, len(dataPairs))
							for _, kv := range dataPairs {
								parts := strings.SplitN(kv, "=", 2)
								kvMap[parts[0]] = parts[1]
							}
							uploadProgress.startedAt = time.Now()
							result, err = c.EncryptData(rcpt, kvMap, opts)
						default:
							uploadProgress.startedAt = time.Now()
							result, err = c.EncryptText(rcpt, string(stdinData), opts)
						}
						if err != nil {
							dbgErr("encrypt", err)
							return "", err
						}
						return fmt.Sprintf("type=%s, size=%s", result.PayloadType, formatBytes(result.EncryptedSize)), nil
					},
				}
				if err := runPipeline("Encrypt & Send", []step{stepDef}, nil); err != nil {
					if firstErr == nil {
						firstErr = err
					}
					fmt.Fprintf(os.Stderr, "%sds.encrypt:%s ✗ %s: %v\n", ansiRed, ansiReset, rcpt, err)
					continue
				}
				results = append(results, result)
			}

			if len(results) == 0 {
				if firstErr != nil {
					return firstErr
				}
				return fmt.Errorf("no secrets were sent")
			}

			// ── Summary ──
			fmt.Fprintln(os.Stderr)
			if len(recipients) == 1 {
				result := results[0]
				printKeyValue("Secret ID", result.Secret.ID)
				printKeyValue("Name", result.Secret.Name)
				printKeyValue("To", recipients[0])
				printKeyValue("Type", result.PayloadType)
				if result.Archived && result.ArchiveEntryCount > 0 {
					printKeyValue("Files", fmt.Sprintf("%d (archived)", result.ArchiveEntryCount))
				} else if result.FilesCount > 0 {
					printKeyValue("Files", fmt.Sprintf("%d", result.FilesCount))
				}
				// Three-line split mirrors what the frontend's integrity panel
				// shows so a side-by-side compare reads identically:
				//   Original Size   – plaintext bytes before any compression
				//   Size            – HPKE envelope bytes uploaded to storage
				//   Compression     – algo + reduction ratio only (no
				//                     intermediate "compressed-but-not-encrypted"
				//                     size, which doesn't appear on the server
				//                     and confuses readers comparing surfaces)
				if result.Compressed && result.OriginalSize > 0 {
					printKeyValue("Original Size", formatBytes(result.OriginalSize))
				}
				printKeyValue("Size", formatBytes(result.EncryptedSize)+" encrypted")
				if result.Compressed && result.OriginalSize > 0 {
					reduction := 100 - result.CompressionRatio
					printKeyValue("Compression", fmt.Sprintf("%s (%.0f%% reduction)",
						strings.ToUpper(result.Compression), reduction))
				}
				printKeyValue("Sender", result.SenderFingerprint[:16])
				printKeyValue("Recipient", result.RecipientFingerprint[:16])
			} else {
				printKeyValue("Sent", fmt.Sprintf("%d/%d recipients", len(results), len(recipients)))
				if groupName != "" {
					printKeyValue("Group", groupName)
				}
				printKeyValue("Name", results[0].Secret.Name)
				printKeyValue("Type", results[0].PayloadType)
				if results[0].Archived && results[0].ArchiveEntryCount > 0 {
					printKeyValue("Files", fmt.Sprintf("%d (archived)", results[0].ArchiveEntryCount))
				} else if results[0].FilesCount > 0 {
					printKeyValue("Files", fmt.Sprintf("%d", results[0].FilesCount))
				}
				printKeyValue("Size", formatBytes(results[0].EncryptedSize)+" encrypted (per recipient)")
				printKeyValue("Sender", results[0].SenderFingerprint[:16])
				for _, r := range results {
					fmt.Fprintf(os.Stderr, "  %s•%s %s  %s\n", ansiDim, ansiReset, r.Secret.ID, recipientForResult(recipients, results, r))
				}
			}
			if ttl != "" {
				printKeyValue("TTL", ttl)
			}
			if len(normalizedIPs) > 0 {
				printKeyValue("IP Lock", strings.Join(normalizedIPs, ", "))
			}
			fmt.Fprintln(os.Stderr)

			if firstErr != nil {
				return fmt.Errorf("some recipients failed: %w", firstErr)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&recipientEmail, "to", "t", "", "Recipient email (default: self)")
	cmd.Flags().StringVarP(&groupName, "group", "g", "", "Send to all members of this org group (excluding self)")
	cmd.Flags().StringVarP(&name, "name", "n", "", "Secret name (defaults to filename or timestamp)")
	cmd.Flags().StringSliceVarP(&inputFiles, "file", "f", nil, "Files to encrypt (can be repeated)")
	cmd.Flags().StringSliceVarP(&dataPairs, "data", "d", nil, "Key-value pair (KEY=VALUE), can be repeated")
	cmd.Flags().StringVar(&ttl, "ttl", "", "Time-to-live (e.g. \"24h\", \"7d\", \"30m\")")
	cmd.Flags().StringSliceVar(&allowedIPs, "ip", nil, "Allowed IP address or CIDR (repeatable or comma-separated, e.g. --ip 1.1.1.1/32,2.2.2.2/30)")
	cmd.Flags().BoolVar(&skipHidden, "skip-hidden", false, "Skip hidden files and directories (dotfiles)")
	cmd.Flags().BoolVarP(&forceArchive, "archive", "a", false, "Archive files as tar.zst regardless of file count (hides file metadata from server)")
	cmd.Flags().BoolVar(&forceArchive, "hide-metadata", false, "Alias for --archive: bundle files so individual names/sizes are not sent to the server")
	cmd.Flags().StringVarP(&identityFP, "identity", "i", "", "Use a specific local identity (fingerprint or prefix) instead of primary")
	cmd.Flags().IntVar(&uploadThreads, "threads", 0, "Parallel multipart upload threads (0=SDK default of 4, 1=serial, max=32). Larger files benefit from more threads on high-bandwidth links.")
	cmd.Flags().IntVar(&presignExpiry, "presign-expiry", 15, "Presigned upload URL lifetime in minutes (allowed: 1-30, default: 15)")
	return cmd
}

func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// splitListFlag splits each entry on commas, semicolons, and whitespace,
// trims, and de-duplicates while preserving order. Lets list flags accept
// any of: --ip a --ip b   |   --ip a,b,c   |   --ip "a, b ; c"
func splitListFlag(values []string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(values))
	for _, v := range values {
		for _, p := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\t' }) {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out
}

// recipientForResult returns the recipient email for a given encrypt result by
// matching the recipient fingerprint position in the slices. Both slices have
// the same ordering since results are appended in recipients order.
func recipientForResult(recipients []string, results []*sdk.EncryptResult, target *sdk.EncryptResult) string {
	for i, r := range results {
		if r == target && i < len(recipients) {
			return recipients[i]
		}
	}
	return ""
}
