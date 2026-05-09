// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"github.com/deepsecret-io/sdk"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// outputFormatted prints data as JSON or YAML to stdout. Returns true if it handled output.
func outputFormatted(format string, data any) (bool, error) {
	switch format {
	case "json":
		out, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return false, err
		}
		fmt.Println(string(out))
		return true, nil
	case "yaml":
		out, err := yaml.Marshal(data)
		if err != nil {
			return false, err
		}
		fmt.Print(string(out))
		return true, nil
	default:
		return false, nil
	}
}

// --- list ---

func newListCmd() *cobra.Command {
	var (
		sent         bool
		vault        bool
		fromEmail    string
		toEmail      string
		limit        int
		page         int
		noPagination bool
		outputFmt    string
	)

	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List secrets (alias: ls)",
		Long: `List secrets with pagination and optional email filter.
By default lists inbox (received) secrets. Use --sent for outgoing secrets,
or --vault for secrets you encrypted to yourself (your personal vault).

Examples:
  secret list                                   # inbox (received), page 1
  secret list --sent                            # sent secrets
  secret list --vault                           # secrets you encrypted to yourself
  secret list --from alice@example.com           # inbox from specific sender
  secret list --sent --to bob@example.com        # sent to specific recipient
  secret list --page 2 --limit 50               # page 2, 50 per page
  secret list --no-pagination                    # all secrets at once`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate limit
			if limit < 1 {
				limit = 20
			}
			if limit > 1000 {
				limit = 1000
			}
			if page < 1 {
				page = 1
			}

			// Mutually exclusive view selectors. The UI mirrors this with
			// Inbox / Sent / Vault tabs; the CLI matches one-to-one.
			if sent && vault {
				return fmt.Errorf("--sent and --vault are mutually exclusive")
			}
			if vault && (fromEmail != "" || toEmail != "") {
				return fmt.Errorf("--vault filters self-sends only; --from / --to do not apply")
			}

			// Vault is sender-side (self-sends): fetch the sent list and
			// filter client-side to rows where sender_id == recipient_id.
			view := "inbox"
			dir := "received"
			if sent {
				dir = "sent"
				view = "sent"
			}
			if vault {
				dir = "sent"
				view = "vault"
			}

			// Validate filter flags match direction
			if sent && fromEmail != "" {
				return fmt.Errorf("use --to (not --from) to filter sent secrets by recipient")
			}
			if !sent && !vault && toEmail != "" {
				return fmt.Errorf("use --from (not --to) to filter inbox secrets by sender")
			}

			// Resolve the email filter: --from for inbox, --to for sent.
			// Vault has no email filter (self-only).
			filterEmail := fromEmail
			if sent {
				filterEmail = toEmail
			}

			dbg("list", "view=%s direction=%s filter=%s limit=%d page=%d", view, dir, filterEmail, limit, page)

			c, err := newAuthenticatedClient()
			if err != nil {
				return err
			}

			queryLimit := limit
			offset := 0
			if noPagination {
				queryLimit = 10000
			} else {
				offset = (page - 1) * queryLimit
			}

			// All three views apply a client-side self-send filter: vault
			// keeps only self-sends, inbox/sent exclude them (matching the
			// UI's Inbox / Sent / Vault separation). Server-side pagination
			// would over- or under-count after the filter, so fetch large
			// and slice locally.
			queryLimit = 10000
			offset = 0

			logInfo("ds.list", fmt.Sprintf("fetching %s secrets (page=%d, limit=%d)", view, page, limit))

			secretsList, _, err := c.ListSecrets(dir, sdk.ListOptions{
				Limit:  queryLimit,
				Offset: offset,
				Email:  filterEmail,
			})
			if err != nil {
				return err
			}

			filtered := secretsList[:0]
			for _, s := range secretsList {
				selfSend := s.SenderID == s.RecipientID
				if view == "vault" && !selfSend {
					continue
				}
				if view != "vault" && selfSend {
					continue
				}
				filtered = append(filtered, s)
			}
			secretsList = filtered
			total := len(filtered)
			if !noPagination {
				localOffset := (page - 1) * limit
				if localOffset > len(secretsList) {
					localOffset = len(secretsList)
				}
				end := localOffset + limit
				if end > len(secretsList) {
					end = len(secretsList)
				}
				secretsList = secretsList[localOffset:end]
				offset = localOffset
				queryLimit = limit
			}

			if handled, err := outputFormatted(outputFmt, map[string]any{"secrets": secretsList, "total": total}); handled || err != nil {
				return err
			}

			if total == 0 {
				printDim("No secrets found.")
				return nil
			}

			headerLabel := "Inbox"
			switch view {
			case "sent":
				headerLabel = "Sent"
			case "vault":
				headerLabel = "Vault"
			}
			header := headerLabel + " secrets"
			if filterEmail != "" {
				if sent {
					header += " to " + filterEmail
				} else {
					header += " from " + filterEmail
				}
			}
			if !noPagination {
				showing := len(secretsList)
				header += fmt.Sprintf(" (%d-%d of %d)", offset+1, offset+showing, total)
			} else {
				header += fmt.Sprintf(" (%d)", total)
			}
			printHeader(header)
			fmt.Fprintln(os.Stderr)

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			switch view {
			case "received":
				fallthrough
			case "inbox":
				fmt.Fprintf(w, "  ID\tFROM\tNAME\tFILES\tREVS\tSIZE\tDATE\n")
				fmt.Fprintf(w, "  --\t----\t----\t-----\t----\t----\t----\n")
			case "sent":
				fmt.Fprintf(w, "  ID\tTO\tNAME\tFILES\tREVS\tSIZE\tDATE\n")
				fmt.Fprintf(w, "  --\t--\t----\t-----\t----\t----\t----\n")
			case "vault":
				fmt.Fprintf(w, "  ID\tNAME\tFILES\tREVS\tSIZE\tDATE\n")
				fmt.Fprintf(w, "  --\t----\t-----\t----\t----\t----\n")
			}
			for _, s := range secretsList {
				filesStr := "-"
				if s.FilesCount > 0 {
					filesStr = fmt.Sprintf("%d", s.FilesCount)
				}
				if view == "vault" {
					fmt.Fprintf(w, "  %s\t%s\t%s\t%d\t%s\t%s\n",
						s.ID,
						ellipsis(s.Name, 25),
						filesStr,
						s.RevisionCount,
						formatBytes(s.TotalSize),
						s.UpdatedAt.Format("2006-01-02 15:04"),
					)
					continue
				}
				contact := s.SenderEmail
				if dir == "sent" {
					contact = s.RecipientEmail
				}
				fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%d\t%s\t%s\n",
					s.ID,
					ellipsis(contact, 25),
					ellipsis(s.Name, 25),
					filesStr,
					s.RevisionCount,
					formatBytes(s.TotalSize),
					s.UpdatedAt.Format("2006-01-02 15:04"),
				)
			}
			w.Flush()

			// Pagination hint
			if !noPagination && offset+len(secretsList) < total {
				fmt.Fprintf(os.Stderr, "\n  Page %d of %d. Use --page %d for next page.\n", page, (total+queryLimit-1)/queryLimit, page+1)
			}
			fmt.Println()
			return nil
		},
	}

	cmd.Flags().BoolVar(&sent, "sent", false, "List sent secrets (default: inbox/received)")
	cmd.Flags().BoolVar(&vault, "vault", false, "List secrets you encrypted to yourself (your personal vault)")
	cmd.Flags().StringVar(&fromEmail, "from", "", "Filter inbox by sender email")
	cmd.Flags().StringVar(&toEmail, "to", "", "Filter sent secrets by recipient email (use with --sent)")
	cmd.Flags().IntVar(&limit, "limit", 20, "Number of secrets per page")
	cmd.Flags().IntVar(&page, "page", 1, "Page number")
	cmd.Flags().BoolVar(&noPagination, "no-pagination", false, "Show all secrets without pagination")
	cmd.Flags().StringVarP(&outputFmt, "output", "o", "", "Output format: json or yaml")
	return cmd
}

// --- delete ---

func newDescribeCmd() *cobra.Command {
	var (
		allRevisions bool
		revisionID   string
		outputFmt    string
	)

	cmd := &cobra.Command{
		Use:     "describe [secret-id]",
		Aliases: []string{"desc"},
		Short:   "Show secret metadata (alias: desc)",
		Long: `Display full metadata for a secret including sender, recipient, policies,
revision details, file attachments, and integrity information.

By default, only the latest revision is shown. Use --all to show all revisions,
or --revision to show a specific one.

Examples:
  secret describe abc123-...                    # latest revision only
  secret desc abc123-... --all                  # all revisions
  secret desc abc123-... -r REV_ID              # specific revision`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dbg("describe", "secret_id=%s all_revisions=%v", args[0], allRevisions)
			c, err := newAuthenticatedClient()
			if err != nil {
				return err
			}

			secretID := args[0]

			logInfo("ds.describe", fmt.Sprintf("fetching secret id=%s", secretID[:12]))

			detail, err := c.DescribeSecretFull(secretID)
			if err != nil {
				return fmt.Errorf("describe: %w", err)
			}
			s := detail.Secret

			// Structured output
			if outputFmt == "json" || outputFmt == "yaml" {
				_, err := outputFormatted(outputFmt, detail)
				return err
			}

			// kubectl-style: same structure as JSON/YAML, just human-formatted
			w := os.Stderr
			kv := func(key, val string) {
				fmt.Fprintf(w, "%-30s%s\n", key+":", val)
			}

			kv("Name", s.Name)
			kv("ID", s.ID)
			kv("Sender ID", s.SenderID)
			kv("Sender Email", s.SenderEmail)
			if s.SenderName != "" {
				kv("Sender Name", s.SenderName)
			}
			kv("Recipient ID", s.RecipientID)
			kv("Recipient Email", s.RecipientEmail)
			if s.RecipientName != "" {
				kv("Recipient Name", s.RecipientName)
			}
			kv("Latest Revision ID", s.LatestRevisionID)
			kv("Revision Count", fmt.Sprintf("%d", s.RevisionCount))
			kv("Total Size", fmt.Sprintf("%d", s.TotalSize))
			// When the secret was sent with --archive (or auto-archived), the
			// server stores FilesCount=0 by design — the archive hides
			// per-file metadata. Render that distinction instead of a bare 0
			// so the user understands "0" doesn't mean "no files".
			kv("Files Count", formatFilesCount(s.FilesCount, secretLatestArchived(detail, s.LatestRevisionID)))
			kv("Created At", s.CreatedAt.Format(time.RFC3339))
			kv("Updated At", s.UpdatedAt.Format(time.RFC3339))
			if s.ExpiresAt != "" {
				kv("Expires At", s.ExpiresAt)
			}
			if len(s.AllowedIPs) > 0 {
				kv("Allowed IPs", strings.Join(s.AllowedIPs, ", "))
			}

			// Revisions — same fields as JSON revisions[]
			if len(detail.Revisions) > 0 {
				var visible []sdk.RevisionInfo

				if revisionID != "" {
					for _, r := range detail.Revisions {
						if r.ID == revisionID {
							visible = append(visible, r)
							break
						}
					}
					if len(visible) == 0 {
						return fmt.Errorf("revision %s not found", revisionID)
					}
				} else if allRevisions {
					for i := len(detail.Revisions) - 1; i >= 0; i-- {
						visible = append(visible, detail.Revisions[i])
					}
				} else {
					for _, r := range detail.Revisions {
						if r.ID == s.LatestRevisionID {
							visible = append(visible, r)
							break
						}
					}
					if len(visible) == 0 {
						visible = detail.Revisions[:1]
					}
				}

				for i, r := range visible {
					if i == 0 {
						fmt.Fprintf(w, "Revisions:\n")
					}
					rkv := func(key, val string) {
						fmt.Fprintf(w, "  %-28s%s\n", key+":", val)
					}
					ikv := func(key, val string) {
						fmt.Fprintf(w, "    %-30s%s\n", key+":", val)
					}

					rkv("ID", r.ID)
					rkv("Revision Number", fmt.Sprintf("%d", r.RevisionNumber))
					rkv("Size", fmt.Sprintf("%d", r.Size))
					rkv("Files Count", formatFilesCount(r.FilesCount, isArchivedRevision(r)))
					if r.StorageName != "" {
						rkv("Storage Name", r.StorageName)
					}
					rkv("Created At", r.CreatedAt)
					fmt.Fprintf(w, "  Integrity:\n")
					ikv("Protocol Version", r.Integrity.ProtocolVersion)
					ikv("Cipher Suite", r.Integrity.CipherSuite)
					ikv("KDF", r.Integrity.KDF)
					if r.Integrity.Encryption != "" {
						ikv("Encryption", r.Integrity.Encryption)
					}
					if r.Integrity.KEM != "" {
						ikv("KEM", r.Integrity.KEM)
					}
					if r.Integrity.Signing != "" {
						ikv("Signing", r.Integrity.Signing)
					}
					if r.Integrity.Serialization != "" {
						ikv("Serialization", r.Integrity.Serialization)
					}
					ikv("Payload Type", r.Integrity.PayloadType)
					ikv("Compressed", fmt.Sprintf("%v", r.Integrity.Compressed))
					if r.Integrity.Compression != "" {
						ikv("Compression", r.Integrity.Compression)
					}
					if r.Integrity.CompressionRatio > 0 {
						ikv("Compression Ratio", fmt.Sprintf("%.2f", r.Integrity.CompressionRatio))
					}
					if r.Integrity.OriginalSize > 0 {
						ikv("Original Size", fmt.Sprintf("%d", r.Integrity.OriginalSize))
					}
					ikv("Key Fingerprint", fingerprintWithStatus(r.Integrity.KeyFingerprint, r.Integrity.SenderKeyStatus))
					ikv("Recipient Key Fingerprint", fingerprintWithStatus(r.Integrity.RecipientKeyFingerprint, r.Integrity.RecipientKeyStatus))
					ikv("Checksum SHA256", r.Integrity.ChecksumSHA256)
					ikv("Etag", r.Integrity.Etag)
					if len(r.FilesMeta) > 0 {
						fmt.Fprintf(w, "  Files Meta:\n")
						for _, f := range r.FilesMeta {
							fmt.Fprintf(w, "    - %-28s%s\n", "Name:", f.Name)
							fmt.Fprintf(w, "      %-28s%d\n", "Size:", f.Size)
							fmt.Fprintf(w, "      %-28s%s\n", "SHA256:", f.SHA256)
						}
					}
				}
			}

			return nil
		},
	}

	cmd.Flags().BoolVarP(&allRevisions, "all", "a", false, "Show all revisions")
	cmd.Flags().StringVarP(&revisionID, "revision", "r", "", "Show a specific revision by ID")
	cmd.Flags().StringVarP(&outputFmt, "output", "o", "", "Output format: json or yaml")
	cmd.AddCommand(newDescribeGroupCmd())
	return cmd
}

func newDescribeGroupCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "group <name>",
		Short: "Show a group's members (alias: secret describe group <name>)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return describeGroup(args[0])
		},
	}
}

func newDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "delete [secret-id...]",
		Aliases: []string{"del", "rm"},
		Short:   "Delete secrets (alias: del, rm)",
		Long: `Delete secrets by their IDs. You can only delete secrets where you are
the sender or recipient.

Examples:
  secret delete abc123-...
  secret delete abc123-... def456-...`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dbg("delete", "ids=%v", args)
			c, err := newAuthenticatedClient()
			if err != nil {
				return err
			}

			for _, id := range args {
				if _, err := uuid.Parse(id); err != nil {
					return fmt.Errorf("invalid secret ID %q: %w", id, err)
				}
			}

			dbg("delete", "deleting %d secret(s)", len(args))

			if err := c.DeleteSecrets(args); err != nil {
				return fmt.Errorf("delete secrets: %w", err)
			}

			printSuccess(fmt.Sprintf("Deleted %d secret(s)", len(args)))
			return nil
		},
	}

	return cmd
}

// --- policy ---

func newPolicyCmd() *cobra.Command {
	var (
		ttl        string
		allowedIPs []string
		clearTTL   bool
		clearIPs   bool
	)

	cmd := &cobra.Command{
		Use:     "policy [secret-id]",
		Aliases: []string{"pol"},
		Short:   "Update secret policies (alias: pol)",
		Long: `Update or remove policies on an existing secret. Only the sender can modify policies.

Use --clear-* flags to remove a policy entirely.

Examples:
  secret policy abc123-... --ttl 48h
  secret policy abc123-... --ip 10.0.0.0/8
  secret policy abc123-... --clear-ttl --clear-ips`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			secretID := args[0]
			if _, err := uuid.Parse(secretID); err != nil {
				return fmt.Errorf("invalid secret ID: %w", err)
			}

			c, err := newAuthenticatedClient()
			if err != nil {
				return err
			}

			update := sdk.PolicyUpdate{}
			hasChanges := false

			if cmd.Flags().Changed("ttl") {
				d, err := parseDuration(ttl)
				if err != nil {
					return fmt.Errorf("invalid --ttl: %w", err)
				}
				secs := int(d.Seconds())
				update.TTLSeconds = &secs
				hasChanges = true
			}
			if clearTTL {
				zero := 0
				update.TTLSeconds = &zero
				hasChanges = true
			}

			if cmd.Flags().Changed("ip") {
				update.AllowedIPs = &allowedIPs
				hasChanges = true
			}
			if clearIPs {
				empty := []string{}
				update.AllowedIPs = &empty
				hasChanges = true
			}

			if !hasChanges {
				return fmt.Errorf("no policy flags specified. Use --ttl, --ip, or --clear-* flags")
			}

			logInfo("ds.policy", fmt.Sprintf("updating policies for secret=%s", secretID[:12]))
			updated, err := c.UpdatePolicy(secretID, update)
			if err != nil {
				return err
			}

			printSuccess(fmt.Sprintf("Policies updated for %s (%s)", updated.ID, updated.Name))
			fmt.Fprintln(os.Stderr)
			if updated.ExpiresAt != nil {
				printKeyValue("TTL", "expires "+*updated.ExpiresAt)
			} else {
				printKeyValue("TTL", "none")
			}
			if len(updated.AllowedIPs) > 0 {
				printKeyValue("IP Lock", strings.Join(updated.AllowedIPs, ", "))
			} else {
				printKeyValue("IP Lock", "none")
			}
			fmt.Fprintln(os.Stderr)

			return nil
		},
	}

	cmd.Flags().StringVar(&ttl, "ttl", "", "Set TTL (e.g. \"24h\", \"7d\")")
	cmd.Flags().StringSliceVar(&allowedIPs, "ip", nil, "Set allowed IPs/CIDRs (replaces existing)")
	cmd.Flags().BoolVar(&clearTTL, "clear-ttl", false, "Remove TTL policy")
	cmd.Flags().BoolVar(&clearIPs, "clear-ips", false, "Remove IP lock policy")

	return cmd
}

// --- shared helpers ---

// resolveIdentityName resolves a local identity by fingerprint or prefix.
// If empty, auto-selects the first (or only) available key.
// Supports prefix matching: "e3a80e" matches "e3a80e8489cc6147..."
func resolveIdentityName(fpOrPrefix string) string {
	entries, err := os.ReadDir(keysDir())
	if err != nil {
		return fpOrPrefix
	}

	var keyFiles []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			keyFiles = append(keyFiles, strings.TrimSuffix(e.Name(), ".json"))
		}
	}

	if len(keyFiles) == 0 {
		return fpOrPrefix
	}

	// If no fingerprint specified, auto-select the only key or first key
	if fpOrPrefix == "" {
		if len(keyFiles) == 1 {
			return keyFiles[0]
		}
		fmt.Fprintf(os.Stderr, "  Multiple identities found, using: %s\n\n", keyFiles[0][:16])
		return keyFiles[0]
	}

	// Exact match
	for _, kf := range keyFiles {
		if kf == fpOrPrefix {
			return kf
		}
	}

	// Prefix match
	var matches []string
	for _, kf := range keyFiles {
		if strings.HasPrefix(kf, fpOrPrefix) {
			matches = append(matches, kf)
		}
	}
	if len(matches) == 1 {
		return matches[0]
	}
	if len(matches) > 1 {
		fmt.Fprintf(os.Stderr, "  Ambiguous fingerprint prefix '%s' matches %d keys:\n", fpOrPrefix, len(matches))
		for _, m := range matches {
			fmt.Fprintf(os.Stderr, "    %s\n", m)
		}
		fmt.Fprintln(os.Stderr)
		return "" // return empty to force error downstream
	}

	return fpOrPrefix
}

func ellipsis(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

// isArchivedRevision reports whether the revision was sent as a single
// tar.zst archive bundling multiple files. The compression label is the
// canonical signal — it's set to "tar+zstd" only by the archive code path.
func isArchivedRevision(r sdk.RevisionInfo) bool {
	return r.Integrity.Compression == "tar+zstd"
}

// secretLatestArchived reports whether the secret's latest revision was
// sent archived. Returns false if the latest revision isn't loaded in the
// detail (older API responses, partial loads).
func secretLatestArchived(detail *sdk.SecretDetail, latestRevisionID string) bool {
	if detail == nil {
		return false
	}
	for _, r := range detail.Revisions {
		if r.ID == latestRevisionID {
			return isArchivedRevision(r)
		}
	}
	return false
}

// formatFilesCount renders the per-revision FilesCount for the user. When
// the revision was archived, the server-stored count is 0 by design (the
// archive hides per-file metadata) — render that as "archived (entries
// hidden)" instead of a bare "0" so the user doesn't read it as "no files".
func formatFilesCount(count int, archived bool) string {
	if archived {
		if count > 0 {
			return fmt.Sprintf("%d (archived)", count)
		}
		return "archived (entries hidden)"
	}
	return fmt.Sprintf("%d", count)
}

func formatBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	if strings.HasSuffix(s, "d") {
		numStr := strings.TrimSuffix(s, "d")
		var days int
		if _, err := fmt.Sscanf(numStr, "%d", &days); err != nil || days <= 0 {
			return 0, fmt.Errorf("invalid days: %s", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, fmt.Errorf("duration must be positive")
	}
	return d, nil
}


// fingerprintWithStatus annotates an identity fingerprint with its trust
// status for inline display in revision details. Mirrors the colored
// indicator in the web UI:
//
//   primary   → green   "(primary identity)"
//   secondary → cyan    "(non-primary identity)"
//   invalid   → red     "(identity deleted)"
//
// When the fingerprint is empty or the status is unset, returns the
// fingerprint as-is so the details surface degrades gracefully.
func fingerprintWithStatus(fp string, status *string) string {
	if fp == "" || status == nil || *status == "" {
		return fp
	}
	switch *status {
	case "primary":
		return fp + " " + ansiGreen + "(primary identity)" + ansiReset
	case "secondary":
		return fp + " " + ansiCyan + "(non-primary identity)" + ansiReset
	case "invalid":
		return fp + " " + ansiRed + "(identity deleted)" + ansiReset
	default:
		return fp
	}
}
