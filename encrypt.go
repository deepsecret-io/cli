// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

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
		local           bool
		localOutput     string
		localOverwrite  bool
	)

	cmd := &cobra.Command{
		Use:     "encrypt [files...]",
		Aliases: []string{"enc"},
		Short:   "Encrypt data locally and upload it as a secret (alias: enc)",
		Long: `Encrypt files, directories, key-value pairs or text from stdin on this
machine for one or more recipients with hybrid post-quantum encryption
(X25519 + ML-KEM-768 + AES-256-GCM), then upload the encrypted result as one
secret: the payload is encrypted and uploaded once, with a key wrap for
every recipient. You are a recipient only when you list yourself; with no
recipients it is sent to you. To encrypt without uploading, use --local.

Files and directories can be given as arguments or with --file; directories
keep their structure. Sending again under an existing name adds a revision
and must list everyone who has access now, or add --revoke-missing.

--archive bundles the files into one zstd-compressed tar before encrypting,
so the server sees one opaque payload: no file names, sizes or structure.

Large files stream from disk, so memory stays flat at any size. The
encrypted copy is kept in ~/.deepsecret/uploads (DEEPSECRET_TMPDIR moves it)
until the upload finishes, which needs that much free disk space. The upload
adapts its parallel connections to the link, and "secret resume" finishes
an interrupted one. --progress shows each connection as it goes, and --debug
the transfer plan and every change to it.

--local writes the sealed secret to a .cbor file instead: nothing is
uploaded and no secret is created. Recipients' public keys still come from
your account. Recipients open the file with "secret decrypt --local".`,
		Example: `  secret encrypt config.yaml -t alice@example.com
  secret encrypt config.yaml -t alice@example.com,bob@example.com
  secret encrypt auth.service keys.service traefik/ -t alice@example.com
  secret encrypt -f config.yaml                         # send to yourself
  secret encrypt -d DB_PASS=secret -d API_KEY=abc -t alice@example.com
  secret encrypt key.pem -t alice@example.com --ttl 24h --ip 10.0.0.0/8
  secret encrypt . --archive -t alice@example.com       # hide file names and sizes
  secret encrypt db.env -g engineering                  # every other member of a group
  secret encrypt db.env -n db.env -t alice@example.com --revoke-missing
  secret encrypt db.env -t alice@example.com --local    # writes ./db.env.cbor, sends nothing`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Merge positional args into inputFiles
			inputFiles = append(inputFiles, args...)

			// Flag values are checked as they are parsed, and conflicting
			// flags by cobra; what is left depends on several flags.
			if len(inputFiles) > 0 && len(dataPairs) > 0 {
				return fmt.Errorf("give files or --data, not both")
			}
			if err := requireFlag(cmd, "local", "output", "overwrite"); err != nil {
				return err
			}
			if cmd.Flags().Changed("group") {
				if groupName = strings.TrimSpace(groupName); groupName == "" {
					return fmt.Errorf("--group needs a group name")
				}
			}
			if localOutput != "" {
				if err := checkOutputFile("output", localOutput); err != nil {
					return err
				}
			}
			for _, f := range inputFiles {
				if strings.TrimSpace(f) == "" {
					return fmt.Errorf("a file argument is empty")
				}
			}
			logInputs(inputFiles)

			// Read stdin early if no -f or -d (before network calls, needs raw terminal)
			var stdinData []byte
			if len(inputFiles) == 0 && len(dataPairs) == 0 {
				if stat, err := os.Stdin.Stat(); err == nil && stat.Mode()&os.ModeCharDevice != 0 {
					fmt.Fprintf(os.Stderr, "Enter the text to encrypt, then press %s to finish:\n", stdinEOFKeys)
				}
				var err error
				stdinData, err = io.ReadAll(os.Stdin)
				if err != nil {
					return fmt.Errorf("could not read stdin: %w", err)
				}
				if len(bytes.TrimSpace(stdinData)) == 0 {
					return withDetail(errors.New("nothing to encrypt: the input is empty"),
						"Give files as arguments or with --file, key-value pairs with --data, or text on stdin.")
				}
			}

			c, err := newAuthenticatedClient()
			if err != nil {
				return err
			}

			// Resolve the recipient list. Sources (in priority order):
			//   1. -g/--group  : every group member except self
			//   2. -t/--to     : the explicit recipients
			//   3. (none)      : send to self
			// Whatever the source, it is one send. Its lines say it
			// uploads; --local only encrypts.
			verb := "Sending to"
			if local {
				verb = "Encrypting for"
			}
			var recipients []string
			recipientsFrom := "--to"
			switch {
			case groupName != "":
				info, err := c.WhoAmI()
				if err != nil {
					return fmt.Errorf("could not fetch your account: %w", apiCause(err))
				}
				group, err := findGroup(c, info, groupName)
				if err != nil {
					return err
				}
				for _, m := range group.Members {
					if m.Email == "" {
						continue
					}
					if strings.EqualFold(m.Email, info.Email) {
						continue // exclude self
					}
					recipients = append(recipients, m.Email)
				}
				if len(recipients) == 0 {
					return withDetail(fmt.Errorf("group %q has no other members to send to", group.Name),
						"Add another member to the group, or leave out --group to send the secret to yourself.")
				}
				groupName, recipientsFrom = group.Name, "--group"
				printSubject("secret", fmt.Sprintf("%s group %q (%d recipient%s)", verb, group.Name, len(recipients), pluralS(len(recipients))))
			case len(recipientEmails) > 0:
				recipients = recipientEmails
			default:
				info, err := c.WhoAmI()
				if err != nil {
					return fmt.Errorf("could not fetch your account: %w", apiCause(err))
				}
				recipients, recipientsFrom = []string{info.Email}, "yourself"
				printSubject("secret", fmt.Sprintf("%s yourself (%s)", verb, info.Email))
			}

			// Normalize list flags: support both repeating (--ip a --ip b) and
			// comma/space-separated (--ip a,b,c) forms, and any mix.
			normalizedIPs := splitListFlag(allowedIPs)

			// Prompt for key password if identity is encrypted
			var keyPassword string
			if identityFP != "" {
				resolved := resolveKeystoreFingerprint(identityFP)
				if isKeyPairEncrypted(resolved) {
					pw, perr := readPassword(fmt.Sprintf("Password for key pair %s: ", crypto.ShortFingerprint(resolved)))
					if perr != nil {
						return perr
					}
					keyPassword = pw
				}
			} else {
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
				ResumeDir:            uploadsDir(),
				PresignExpiryMinutes: presignExpiry,
				Logger:               logger,
			}

			// Live progress: encrypting, then each connection of the
			// upload.
			progress := newSendProgress()
			if local {
				progress = newStageProgress("encrypting")
			}
			opts.OnEncryptProgress = progress.pre.set
			opts.UploadStatus = &progress.transfer

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

			// A local file is named after the input unless -o says where.
			if local {
				opts.LocalFile = localOutput
				if opts.LocalFile == "" {
					opts.LocalFile = localFileName(name, inputFiles, opts.Name)
				}
				opts.LocalOverwrite = localOverwrite
			}

			// The settings this send resolved to, once, before the SDK logs
			// its own plan.
			settings := []any{"recipients", len(recipients), "recipients_from", recipientsFrom, "identity", identityLabel(identityFP)}
			if local {
				settings = append(settings, "local_file", opts.LocalFile)
			} else {
				settings = append(settings, "threads", threadCountLabel(uploadThreads), "presign_expiry", time.Duration(presignExpiry)*time.Minute)
			}
			api.Module(logger, "encrypt").Debug("options", settings...)

			// One send: the SDK encrypts the payload once on this machine,
			// wraps its key for every recipient, and uploads it once.
			label, done := "Encrypting and uploading", "Upload complete"
			if len(recipients) > 1 {
				label = fmt.Sprintf("Encrypting and uploading for %d recipients", len(recipients))
			}
			if local {
				label, done = "Encrypting to "+opts.LocalFile, "Encryption complete"
			}
			var result *sdk.EncryptResult
			stepDef := step{
				label: label,
				done:  done,
				live:  progress,
				action: func() (string, error) {
					var err error
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
						return "", err
					}
					if local {
						return "", nil
					}
					return "id=" + shortID(result.Secret.ID), nil
				},
			}
			if err := runPipeline("secret", []step{stepDef}); err != nil {
				var interrupted *sdk.UploadInterruptedError
				if errors.As(err, &interrupted) {
					return withDetail(err, resumeDetail(interrupted.Upload.RevisionID))
				}
				// A send under the name of an existing secret adds a revision
				// to it. The name may have come from the input's file name,
				// so say so, and how to send a new secret instead.
				if errors.Is(err, api.ErrConflict) && !revokeMissing && strings.Contains(err.Error(), "leaves out") {
					return withDetail(err, fmt.Sprintf("You already have a secret named %q, and this send would add a revision to it.\n"+
						"To send a new secret instead, give it another name with -n.\n"+
						"To update %q, list everyone who should keep access with --to, or add --revoke-missing.", safe(opts.Name), safe(opts.Name)))
				}
				return err
			}

			// ── Summary ──
			fmt.Fprintln(os.Stderr)
			if local {
				printKeyValue("File", safe(result.LocalFile))
			} else {
				printKeyValue("Secret ID", safe(result.Secret.ID))
				printKeyValue("Name", safe(result.Secret.Name))
			}
			if groupName != "" {
				printKeyValue("Group", safe(groupName))
			}
			printKeyValue("Type", result.PayloadType)
			if result.Archived && result.ArchiveEntryCount > 0 {
				printKeyValue("Files", archivedFiles(result.ArchiveFileCount, result.ArchiveEntryCount))
			} else if result.FilesCount > 0 {
				printKeyValue("Files", fmt.Sprintf("%d", result.FilesCount))
			}
			// Three-line split mirrors what the frontend's integrity panel
			// shows so a side-by-side compare reads identically:
			//   Original Size : the files' own bytes, before tar and
			//                   compression
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
				// CompressionRatio is the compressed size as a percentage
				// of the original; an archive is compressed even when that
				// makes it larger.
				change := fmt.Sprintf("%.0f%% reduction", 100-result.CompressionRatio)
				if result.CompressionRatio > 100 {
					change = fmt.Sprintf("%.0f%% larger", result.CompressionRatio-100)
				}
				printKeyValue("Compression", fmt.Sprintf("%s (%s)", strings.ToUpper(result.Compression), change))
			}
			printKeyValue("Sender", crypto.ShortFingerprint(result.SenderFingerprint))
			sentTo := make([]string, len(result.Recipients))
			for i, r := range result.Recipients {
				sentTo[i] = fmt.Sprintf("%s  %s%s%s", safe(r.Email), ansiDim, safe(crypto.ShortFingerprint(r.Fingerprint)), ansiReset)
			}
			printKeyValues("Recipient"+pluralS(len(sentTo)), sentTo)
			if len(result.Revoked) > 0 {
				revoked := make([]string, len(result.Revoked))
				for i, r := range result.Revoked {
					revoked[i] = safe(r.Email)
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
			printFirstUse(result.FirstUse)
			if local {
				printDim("Nothing was uploaded. Send the file over any channel; recipients open it with:")
				printDim("  secret decrypt --local " + safe(filepath.Base(result.LocalFile)))
				fmt.Fprintln(os.Stderr)
			}
			return nil
		},
	}

	f := cmd.Flags()
	// --hide-metadata is another name for --archive.
	f.SetNormalizeFunc(func(_ *pflag.FlagSet, name string) pflag.NormalizedName {
		if name == "hide-metadata" {
			name = "archive"
		}
		return pflag.NormalizedName(name)
	})
	f.VarP(&emailList{&recipientEmails}, "to", "t", "Recipient `email`, repeatable or comma-separated (default: yourself)")
	f.StringVarP(&groupName, "group", "g", "", "Send to every other member of this org `group`, in one send")
	f.BoolVar(&revokeMissing, "revoke-missing", false, "When resending under an existing name, revoke the recipients this send leaves out")
	setGroup(f, groupRecipients, "to", "group", "revoke-missing")

	f.StringArrayVarP(&inputFiles, "file", "f", nil, "File or directory `path` to encrypt, repeatable (or give them as arguments)")
	f.VarP(&kvPairs{&dataPairs}, "data", "d", "A KEY=VALUE pair to encrypt, repeatable")
	f.VarP(&nameFlag{&name}, "name", "n", "Secret `name` (default: the first file's name, or a timestamp)")
	f.BoolVar(&skipHidden, "skip-hidden", false, "Skip hidden files and directories (dotfiles)")
	f.BoolVarP(&forceArchive, "archive", "a", false, "Bundle files into one compressed archive, so the server sees no file names or sizes (alias: --hide-metadata)")
	setGroup(f, groupInput, "file", "data", "name", "skip-hidden", "archive")

	f.Var(&ttlFlag{&ttl}, "ttl", "Expire the secret after this long: 2m to 365d, like 30m, 24h or 7d")
	f.Var(&ipList{&allowedIPs}, "ip", "Allow access only from these IP addresses or CIDR ranges, repeatable or comma-separated (at most 50)")
	setGroup(f, groupPolicies, "ttl", "ip")

	f.BoolVar(&local, "local", false, "Write the encrypted secret to a local .cbor file instead of uploading it")
	f.StringVarP(&localOutput, "output", "o", "", "Output `file` for --local (default: ./<name>.cbor, after -n or the first input)")
	f.BoolVar(&localOverwrite, "overwrite", false, "With --local, replace an existing file at the output path")
	setGroup(f, groupLocal, "local", "output", "overwrite")

	f.VarP(&fingerprintFlag{&identityFP}, "identity", "i", "Sign with this local identity (`fingerprint` or a prefix of 16+ characters) instead of your primary")
	setGroup(f, groupIdentity, "identity")

	f.Var(newIntRange(&uploadThreads, 0, 0, api.MaxUploadThreads, " (0 adapts to the connection, 1 is one at a time)"), "threads", "Parallel part uploads for large files: 0 adapts to the connection, up to 32")
	f.Var(newMinutes(&presignExpiry, 15, 1, 30), "presign-expiry", "Lifetime of the presigned URL of a small, single-request upload: 1m to 30m (large uploads renew theirs)")
	setGroup(f, groupPerformance, "threads", "presign-expiry")

	cmd.MarkFlagsMutuallyExclusive("to", "group")
	cmd.MarkFlagsMutuallyExclusive("file", "data")
	for _, sendOnly := range []string{"ttl", "ip", "revoke-missing", "threads", "presign-expiry"} {
		cmd.MarkFlagsMutuallyExclusive("local", sendOnly)
	}
	return cmd
}

// localFileName is the default --local output: the -n name, else the first
// input's name, else the generated secret name, with the .cbor extension,
// in the current directory.
func localFileName(name string, inputs []string, fallback string) string {
	base := name
	if base == "" && len(inputs) > 0 {
		base = inputs[0]
		if abs, err := filepath.Abs(base); err == nil {
			base = abs
		}
	}
	if base == "" {
		base = fallback
	}
	base = filepath.Base(base)
	if base == "." || base == string(filepath.Separator) || base == "" {
		base = "secret"
	}
	return base + sdk.LocalFileExt
}

// logInputs logs what each input path is, before the SDK reads them.
func logInputs(paths []string) {
	log := api.Module(logger, "input")
	if len(paths) == 0 || !log.Enabled(context.Background(), slog.LevelDebug) {
		return
	}
	for _, p := range paths {
		info, err := os.Stat(p)
		switch {
		case err != nil:
			log.Debug("path unreadable", "path", p, "error", err)
		case info.IsDir():
			log.Debug("path found", "path", p, "type", "directory")
		default:
			log.Debug("path found", "path", p, "type", "file", "size", api.Bytes(info.Size()))
		}
	}
}

// identityLabel is the identity a command uses, for a log field: the
// --identity fingerprint, or "primary".
func identityLabel(fp string) string {
	if fp == "" {
		return "primary"
	}
	return fp
}

func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// archivedFiles is the Files line of a send that went as one archive: its
// regular files, and its entries when folders or links add to them.
func archivedFiles(files, entries int) string {
	switch {
	case files <= 0:
		return fmt.Sprintf("%d entr%s in one archive", entries, map[bool]string{true: "y", false: "ies"}[entries == 1])
	case entries > files:
		return fmt.Sprintf("%d in one archive (%d entries with folders and links)", files, entries)
	}
	return fmt.Sprintf("%d in one archive", files)
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
