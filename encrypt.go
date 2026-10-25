// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/deepsecret-io/sdk"
	"github.com/deepsecret-io/sdk/api"
	"github.com/deepsecret-io/sdk/crypto"
)

func newEncryptCmd() *cobra.Command {
	var (
		recipientEmails []string
		groupName       string
		revokeMissing   bool
		name            string
		inputFiles      []string
		dataPairs       []string
		ttl             string
		allowedIPs      []string
		skipHidden      bool
		forceArchive    bool
		identityFP      string
		uploadThreads   int
		presignExpiry   int
	)

	cmd := &cobra.Command{
		Use:     "encrypt [files...]",
		Aliases: []string{"enc"},
		Short:   "Encrypt and send a secret (alias: enc)",
		Long: `Encrypt files, directories, or key-value pairs for one or more recipients
using hybrid post-quantum encryption (X25519 + ML-KEM-768 + AES-256-GCM).

Files and directories can be passed as positional args or with -f flags.
Directories are recursively included with their structure preserved.

Recipients:
  --to, -t     Recipient email (can be repeated). The payload is encrypted
               and uploaded once, with a key wrap for every recipient. You are
               not a recipient unless you list yourself. Default: yourself.
  --group, -g  Every member of an org group except you, in one send.
  --revoke-missing
               Sending again under an existing name must list everyone who
               has access now. This flag revokes the people it leaves out.

Policies:
  --ttl  Time-to-live (e.g. "24h", "7d", "30m"). Secret expires after this duration.
  --ip   Restrict access to specific IPs or CIDRs (can be repeated).

Privacy:
  --archive, --hide-metadata
      Bundle all files into a single tar.zst archive before encrypting.
      The server only sees one opaque blob: individual file names, sizes,
      and directory structure are never sent as metadata. Use this when
      file metadata itself is sensitive.

Examples:
  secret encrypt config.yaml -t alice@example.com
  secret encrypt config.yaml -t alice@example.com -t bob@example.com
  secret encrypt auth.service keys.service traefik -t alice@example.com
  secret encrypt -f config.yaml                        # send to self
  secret encrypt -d DB_PASS=secret -d API_KEY=abc -t alice@example.com
  secret encrypt -f key.pem -t alice@example.com --ttl 24h
  secret encrypt -f db.env -t alice@example.com --ip 10.0.0.0/8
  secret encrypt -f . --hide-metadata -t alice@example.com  # hide file metadata from server
  secret encrypt -f db.env -g engineering              # one send to every other member of "engineering"
  secret encrypt -f db.env -n db.env -t alice@example.com --revoke-missing  # resend, revoking anyone left out`,
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

			if len(recipientEmails) > 0 && groupName != "" {
				return fmt.Errorf("use either --to or --group, not both")
			}

			// Validate data pair format early
			for _, kv := range dataPairs {
				if !strings.Contains(kv, "=") {
					return fmt.Errorf("invalid --data format %q (expected KEY=VALUE)", kv)
				}
			}

			// Validate the explicit recipient list early, before stdin is
			// read and before any network call.
			if len(recipientEmails) > 0 {
				if err := sdk.ValidateRecipients(recipientEmails); err != nil {
					return err
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

			// Resolve the recipient list. Sources (in priority order):
			//   1. -g/--group  : every group member except self
			//   2. -t/--to     : the explicit recipients
			//   3. (none)      : send to self
			// Whatever the source, it is one send.
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
				groupName = matched.Name
				fmt.Fprintf(os.Stderr, "%sds.encrypt:%s %s→%s sending to group %q (%d recipient%s)\n",
					ansiCyan, ansiReset, ansiDim, ansiReset, matched.Name, len(recipients), pluralS(len(recipients)))
			case len(recipientEmails) > 0:
				recipients = recipientEmails
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
			if revokeMissing {
				logDebug("config", "revoke-missing=true")
			}

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
				RevokeMissing:        revokeMissing,
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

			// One send: the SDK encrypts the payload once, wraps its key for
			// every recipient, and uploads it once.
			label := "Encrypting and uploading"
			if len(recipients) > 1 {
				label = fmt.Sprintf("Encrypting and uploading for %d recipients", len(recipients))
			}
			var result *sdk.EncryptResult
			stepDef := step{
				label:    label,
				transfer: uploadProgress,
				action: func() (string, error) {
					var err error
					uploadProgress.startedAt = time.Now()
					switch {
					case len(inputFiles) > 0:
						result, err = c.EncryptPaths(recipients, inputFiles, opts)
					case len(dataPairs) > 0:
						kvMap := make(map[string]string, len(dataPairs))
						for _, kv := range dataPairs {
							parts := strings.SplitN(kv, "=", 2)
							kvMap[parts[0]] = parts[1]
						}
						result, err = c.EncryptData(recipients, kvMap, opts)
					default:
						result, err = c.EncryptText(recipients, string(stdinData), opts)
					}
					if err != nil {
						dbgErr("encrypt", err)
						return "", err
					}
					return fmt.Sprintf("type=%s, size=%s, recipients=%d", result.PayloadType, formatBytes(result.EncryptedSize), len(result.Recipients)), nil
				},
			}
			if err := runPipeline("Encrypt & Send", []step{stepDef}, nil); err != nil {
				if errors.Is(err, api.ErrConflict) && !revokeMissing {
					fmt.Fprintf(os.Stderr, "  Tip: list everyone who should keep access with --to, or add --revoke-missing to revoke the people this send leaves out\n")
				}
				return err
			}

			// ── Summary ──
			fmt.Fprintln(os.Stderr)
			printKeyValue("Secret ID", result.Secret.ID)
			printKeyValue("Name", result.Secret.Name)
			if groupName != "" {
				printKeyValue("Group", groupName)
			}
			printKeyValue("Type", result.PayloadType)
			if result.Archived && result.ArchiveEntryCount > 0 {
				printKeyValue("Files", fmt.Sprintf("%d (archived)", result.ArchiveEntryCount))
			} else if result.FilesCount > 0 {
				printKeyValue("Files", fmt.Sprintf("%d", result.FilesCount))
			}
			// Three-line split mirrors what the frontend's integrity panel
			// shows so a side-by-side compare reads identically:
			//   Original Size : plaintext bytes before any compression
			//   Size          : the one encrypted payload uploaded to storage,
			//                   shared by every recipient
			//   Compression   : algo + reduction ratio only (no intermediate
			//                   "compressed-but-not-encrypted" size, which
			//                   doesn't appear on the server and confuses
			//                   readers comparing surfaces)
			if result.Compressed && result.OriginalSize > 0 {
				printKeyValue("Original Size", formatBytes(result.OriginalSize))
			}
			printKeyValue("Size", formatBytes(result.EncryptedSize)+" encrypted")
			if result.Compressed && result.OriginalSize > 0 {
				reduction := 100 - result.CompressionRatio
				printKeyValue("Compression", fmt.Sprintf("%s (%.0f%% reduction)",
					strings.ToUpper(result.Compression), reduction))
			}
			printKeyValue("Sender", crypto.ShortFingerprint(result.SenderFingerprint))
			sentTo := make([]string, len(result.Recipients))
			for i, r := range result.Recipients {
				sentTo[i] = fmt.Sprintf("%s  %s%s%s", r.Email, ansiDim, crypto.ShortFingerprint(r.Fingerprint), ansiReset)
			}
			printKeyValues("Recipient"+pluralS(len(sentTo)), sentTo)
			if len(result.Revoked) > 0 {
				revoked := make([]string, len(result.Revoked))
				for i, r := range result.Revoked {
					revoked[i] = r.Email
				}
				printKeyValues("Revoked", revoked)
			}
			if ttl != "" {
				printKeyValue("TTL", ttl)
			}
			if len(normalizedIPs) > 0 {
				printKeyValue("IP Lock", strings.Join(normalizedIPs, ", "))
			}
			fmt.Fprintln(os.Stderr)
			return nil
		},
	}

	cmd.Flags().StringSliceVarP(&recipientEmails, "to", "t", nil, "Recipient email, can be repeated (default: self)")
	cmd.Flags().StringVarP(&groupName, "group", "g", "", "Send to all members of this org group (excluding self), in one send")
	cmd.Flags().BoolVar(&revokeMissing, "revoke-missing", false, "When resending under an existing name, revoke the current recipients this send leaves out")
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
