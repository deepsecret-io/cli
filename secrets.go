// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/deepsecret-io/sdk"
	"github.com/deepsecret-io/sdk/api"
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
By default lists your inbox: the secrets sent to you, and the ones you
encrypted only to yourself. Use --sent for the secrets you sent to others.

Examples:
  secret list                                   # inbox, page 1
  secret list --sent                            # sent secrets
  secret list --from alice@example.com           # inbox from specific sender
  secret list --sent --to bob@example.com        # sent to specific recipient
  secret list --page 2 --limit 50               # page 2, 50 per page
  secret list --no-pagination                    # all secrets at once
  secret list --format json                      # for scripts`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Values are checked as they are parsed, and the view
			// selector (--sent) by cobra; the UI mirrors the views with
			// Inbox / Sent tabs.
			view := "inbox"
			if sent {
				view = "sent"
			}

			// Validate filter flags match direction
			if sent && fromEmail != "" {
				return fmt.Errorf("use --to (not --from) to filter sent secrets by recipient")
			}
			if !sent && toEmail != "" {
				return fmt.Errorf("use --from (not --to) to filter inbox secrets by sender")
			}

			// Resolve the email filter: --from for inbox, --to for sent.
			filterEmail := fromEmail
			if sent {
				filterEmail = toEmail
			}

			c, err := newAuthenticatedClient()
			if err != nil {
				return err
			}

			// The inbox merges two lists and Sent leaves out the secrets
			// sent only to oneself, so server-side pagination would over-
			// or under-count: fetch large and slice locally.
			const fetchLimit = 10000
			var secretsList []sdk.SecretInfo
			if sent {
				all, _, err := c.ListSecrets("sent", sdk.ListOptions{Limit: fetchLimit, Email: toEmail})
				if err != nil {
					return fmt.Errorf("could not list your sent secrets: %w", apiCause(err))
				}
				secretsList = sentSecrets(all)
			} else {
				received, _, err := c.ListSecrets("received", sdk.ListOptions{Limit: fetchLimit, Email: fromEmail})
				if err != nil {
					return fmt.Errorf("could not list your inbox: %w", apiCause(err))
				}
				own, _, err := c.ListSecrets("sent", sdk.ListOptions{Limit: fetchLimit})
				if err != nil {
					return fmt.Errorf("could not list your inbox: %w", apiCause(err))
				}
				secretsList = inboxSecrets(received, own, fromEmail)
			}

			total := len(secretsList)
			offset, end := 0, total
			if !noPagination {
				offset, end = pageBounds(total, page, limit)
			}
			secretsList = secretsList[offset:end]
			api.Module(logger, "secret").Debug("secrets listed", "view", view, "filter", filterEmail, "total", total, "shown", len(secretsList))

			if handled, err := outputFormatted(outputFmt, map[string]any{"secrets": secretsList, "total": total}); handled || err != nil {
				return err
			}

			if total == 0 {
				printDim(emptyListMessage(sent, filterEmail))
				return nil
			}
			pages := (total + limit - 1) / limit
			if len(secretsList) == 0 {
				return withDetail(fmt.Errorf("there is no page %d", page),
					fmt.Sprintf("At %d per page, the %d secret%s take %d page%s.", limit, total, pluralS(total), pages, pluralS(pages)))
			}

			header := "Inbox secrets"
			if sent {
				header = "Sent secrets"
			}
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

			// Rows wait in the tabwriter until Flush, which returns any write error.
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			if sent {
				_, _ = fmt.Fprintf(w, "  ID\tTO\tNAME\tFILES\tREVS\tSIZE\tDATE\n")
				_, _ = fmt.Fprintf(w, "  --\t--\t----\t-----\t----\t----\t----\n")
			} else {
				_, _ = fmt.Fprintf(w, "  ID\tFROM\tNAME\tFILES\tREVS\tSIZE\tDATE\n")
				_, _ = fmt.Fprintf(w, "  --\t----\t----\t-----\t----\t----\t----\n")
			}
			for _, s := range secretsList {
				filesStr := "-"
				if s.FilesCount > 0 {
					filesStr = fmt.Sprintf("%d", s.FilesCount)
				}
				contact := ellipsis(s.SenderEmail, 25)
				if sent {
					contact = recipientsSummary(s.Recipients)
				}
				_, _ = fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%d\t%s\t%s\n",
					safe(s.ID),
					contact,
					ellipsis(s.Name, 25),
					filesStr,
					s.RevisionCount,
					formatBytes(s.TotalSize),
					s.UpdatedAt.Format("2006-01-02 15:04"),
				)
			}
			if err := w.Flush(); err != nil {
				return fmt.Errorf("could not write to stdout: %w", err)
			}

			fmt.Fprintln(os.Stderr)
			if !noPagination && end < total {
				printDim(fmt.Sprintf("Page %d of %d. Show the next with: --page %d", page, pages, page+1))
				fmt.Fprintln(os.Stderr)
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.BoolVar(&sent, "sent", false, "List the secrets you sent to others (default: your inbox)")
	f.Var(&emailFlag{&fromEmail}, "from", "Inbox secrets from this sender `email` only")
	f.Var(&emailFlag{&toEmail}, "to", "With --sent, secrets sent to this recipient `email` only")
	setGroup(f, groupFilters, "sent", "from", "to")
	f.Var(newIntRange(&limit, 20, 1, 1000, ""), "limit", "Secrets per page: 1 to 1000")
	f.Var(newIntRange(&page, 1, 1, 1_000_000, ""), "page", "Page number, from 1")
	f.BoolVar(&noPagination, "no-pagination", false, "Show every secret on one page")
	setGroup(f, groupPagination, "limit", "page", "no-pagination")
	outputFmt = "table"
	f.Var(&enumFlag{&outputFmt, []string{"table", "json", "yaml"}}, "format", "Output format")
	setGroup(f, groupOutput, "format")
	cmd.MarkFlagsMutuallyExclusive("no-pagination", "page")
	cmd.MarkFlagsMutuallyExclusive("no-pagination", "limit")
	return cmd
}

// inboxSecrets merges the inbox, newest first: the secrets received,
// and the ones the caller sent only to themself. Those come from the
// sent list, which keeps one the caller dismissed as its recipient, so
// the received list's copies are left out to list each secret once. A
// sender filter keeps them only when it names the caller.
func inboxSecrets(received, sent []sdk.SecretInfo, fromEmail string) []sdk.SecretInfo {
	inbox := make([]sdk.SecretInfo, 0, len(received))
	for _, s := range received {
		if !s.IsVault() {
			inbox = append(inbox, s)
		}
	}
	for _, s := range sent {
		if s.IsVault() && (fromEmail == "" || strings.EqualFold(s.SenderEmail, fromEmail)) {
			inbox = append(inbox, s)
		}
	}
	sort.SliceStable(inbox, func(i, j int) bool { return inbox[i].UpdatedAt.After(inbox[j].UpdatedAt) })
	return inbox
}

// sentSecrets leaves out the secrets the caller sent only to themself,
// which the inbox lists.
func sentSecrets(sent []sdk.SecretInfo) []sdk.SecretInfo {
	out := make([]sdk.SecretInfo, 0, len(sent))
	for _, s := range sent {
		if !s.IsVault() {
			out = append(out, s)
		}
	}
	return out
}

// pageBounds is where page, of limit secrets each, starts and ends among
// total. A page past the last one is empty.
func pageBounds(total, page, limit int) (start, end int) {
	start = min((page-1)*limit, total)
	return start, min(start+limit, total)
}

// emptyListMessage says that a list of secrets is empty: the sent ones
// (sent), or the inbox, to or from filterEmail when it is set.
func emptyListMessage(sent bool, filterEmail string) string {
	switch {
	case sent && filterEmail != "":
		return "You have sent no secrets to " + filterEmail + "."
	case sent:
		return "You have sent no secrets to others."
	case filterEmail != "":
		return "Your inbox holds no secrets from " + filterEmail + "."
	}
	return "Your inbox is empty."
}

// --- describe ---

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
		Long: `Display full metadata for a secret including sender, recipients, policies,
revision details, file attachments, and integrity information.

By default, only the latest revision is shown. Use --all to show all revisions,
or --revision to show a specific one.

Examples:
  secret describe 3f2a9c1e-...                  # latest revision only
  secret desc 3f2a9c1e-... --all                # all revisions
  secret desc 3f2a9c1e-... -r 7b1d...           # specific revision
  secret desc 3f2a9c1e-... --format yaml`,
		Args: idArgs(1, "secret ID"),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newAuthenticatedClient()
			if err != nil {
				return err
			}

			secretID := args[0]
			detail, err := c.DescribeSecretFull(secretID)
			if err != nil {
				return secretError(err, secretID)
			}
			s := detail.Secret

			// Structured output
			if outputFmt == "json" || outputFmt == "yaml" {
				_, err := outputFormatted(outputFmt, detail)
				return err
			}

			// kubectl-style: same structure as JSON/YAML, just human-formatted
			// Every value comes from the server, so it is printed
			// through safe. The report is built whole and written once,
			// and the error of that write is returned.
			var b strings.Builder
			w := &b
			kv := func(key, val string) {
				fmt.Fprintf(w, "%-30s%s\n", key+":", safe(val))
			}

			kv("Name", s.Name)
			kv("ID", s.ID)
			kv("Sender ID", s.SenderID)
			kv("Sender Email", s.SenderEmail)
			if s.SenderName != "" {
				kv("Sender Name", s.SenderName)
			}
			if len(s.Recipients) == 0 {
				kv("Recipients", "none")
			} else {
				fmt.Fprintf(w, "Recipients:\n")
				for _, r := range s.Recipients {
					fmt.Fprintf(w, "  - %-26s%s\n", "Email:", safe(r.Email))
					if r.Name != "" {
						fmt.Fprintf(w, "    %-26s%s\n", "Name:", safe(r.Name))
					}
					fmt.Fprintf(w, "    %-26s%s\n", "ID:", safe(r.ID))
				}
			}
			if s.DismissedAt != "" {
				kv("Dismissed At", s.DismissedAt)
			}
			kv("Latest Revision ID", s.LatestRevisionID)
			kv("Revision Count", fmt.Sprintf("%d", s.RevisionCount))
			kv("Total Size", fmt.Sprintf("%d", s.TotalSize))
			// When the secret was sent with --archive (or auto-archived), the
			// server stores FilesCount=0 by design: the archive hides
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

			// Revisions: same fields as JSON revisions[]
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
						return withDetail(fmt.Errorf("revision %s not found in secret %s", shortID(revisionID), shortID(s.ID)),
							"List the revisions you can see with: secret describe "+safe(s.ID)+" --all")
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
						fmt.Fprintf(w, "  %-28s%s\n", key+":", safe(val))
					}
					ikv := func(key, val string) {
						fmt.Fprintf(w, "    %-30s%s\n", key+":", safe(val))
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
					fmt.Fprintf(w, "    %-30s%s\n", "Key Fingerprint:", fingerprintWithStatus(r.Integrity.KeyFingerprint, r.Integrity.SenderKeyStatus))
					if len(r.Integrity.Recipients) > 0 {
						fmt.Fprintf(w, "    Recipients:\n")
						for _, rr := range r.Integrity.Recipients {
							fmt.Fprintf(w, "      - %-26s%s\n", "Email:", safe(rr.Email))
							fmt.Fprintf(w, "        %-26s%s\n", "Key Fingerprint:", fingerprintWithStatus(rr.KeyFingerprint, rr.KeyStatus))
						}
					}
					ikv("Checksum SHA256", r.Integrity.ChecksumSHA256)
					ikv("Etag", r.Integrity.Etag)
					if len(r.FilesMeta) > 0 {
						fmt.Fprintf(w, "  Files Meta:\n")
						for _, f := range r.FilesMeta {
							fmt.Fprintf(w, "    - %-28s%s\n", "Name:", safe(f.Name))
							fmt.Fprintf(w, "      %-28s%d\n", "Size:", f.Size)
							fmt.Fprintf(w, "      %-28s%s\n", "SHA256:", safe(f.SHA256))
						}
					}
				}
			}

			_, err = io.WriteString(os.Stderr, b.String())
			return err
		},
	}

	f := cmd.Flags()
	f.BoolVar(&allRevisions, "all", false, "Show every revision")
	f.VarP(&uuidFlag{&revisionID}, "revision", "r", "Show this revision `id` (default: the latest)")
	setGroup(f, groupInput, "all", "revision")
	outputFmt = "table"
	f.Var(&enumFlag{&outputFmt, []string{"table", "json", "yaml"}}, "format", "Output format")
	setGroup(f, groupOutput, "format")
	cmd.MarkFlagsMutuallyExclusive("all", "revision")
	cmd.AddCommand(newDescribeGroupCmd())
	return cmd
}

func newDescribeGroupCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "group <name>",
		Short: "Show a group's members (same as: secret groups describe <name>)",
		Args:  groupNameArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			return describeGroup(args[0])
		},
	}
}

func newDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "delete [secret-id...]",
		Aliases: []string{"del", "rm"},
		Short:   "Delete secrets you sent (alias: del, rm)",
		Long: `Delete secrets by their IDs. Only a secret's sender can delete it; its
recipients lose access to it.

Examples:
  secret delete abc123-...
  secret delete abc123-... def456-...`,
		Args: minIDArgs(1, "secret ID"),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newAuthenticatedClient()
			if err != nil {
				return err
			}

			// The server deletes only the secrets the caller sent, and
			// skips any other without saying so. Check each first, so the
			// command deletes all of them or none, and says which.
			ids := slices.Compact(slices.Sorted(slices.Values(args)))
			me, err := c.ResolveActorID()
			if err != nil {
				return fmt.Errorf("could not fetch your account: %w", apiCause(err))
			}
			for _, id := range ids {
				info, err := c.DescribeSecret(id)
				if err != nil {
					return secretError(err, id)
				}
				if info.SenderID != me {
					return withDetail(fmt.Errorf("you did not send secret %s, so you cannot delete it", shortID(id)),
						"Only a secret's sender can delete it. Nothing was deleted.")
				}
			}

			if err := c.DeleteSecrets(ids); err != nil {
				return fmt.Errorf("could not delete the secret%s: %w", pluralS(len(ids)), apiCause(err))
			}
			api.Module(logger, "secret").Info("secrets deleted", "ids", ids)

			printSuccess(fmt.Sprintf("Deleted %d secret%s.", len(ids), pluralS(len(ids))))
			return nil
		},
	}

	return cmd
}

// --- revoke ---

func newRevokeCmd() *cobra.Command {
	var recipientEmails []string

	cmd := &cobra.Command{
		Use:   "revoke [secret-id]",
		Short: "Revoke recipients of a sent secret",
		Long: `Revoke one or more recipients of a secret you sent. Their access and every
key wrap made for them are deleted, so they can no longer download any
revision. A recipient who already downloaded a revision keeps what they
downloaded. Revoking the last recipient deletes the secret.

Examples:
  secret revoke abc123-... --to bob@example.com
  secret revoke abc123-... -t bob@example.com -t carol@example.com`,
		Args: idArgs(1, "secret ID"),
		RunE: func(cmd *cobra.Command, args []string) error {
			secretID := args[0]

			c, err := newAuthenticatedClient()
			if err != nil {
				return err
			}

			for _, email := range recipientEmails {
				// A 404 here is the secret's or the recipient's access, so
				// the server's message says which.
				res, err := c.RevokeRecipient(secretID, email)
				switch {
				case errors.Is(err, api.ErrForbidden):
					return fmt.Errorf("only the sender of secret %s can revoke its recipients", shortID(secretID))
				case err != nil:
					return fmt.Errorf("could not revoke %s: %w", email, apiCause(err))
				}
				api.Module(logger, "secret").Info("recipient revoked", "secret_id", secretID, "email", res.Email, "secret_deleted", res.SecretDeleted)
				printSuccess(fmt.Sprintf("Revoked %s.", safe(res.Email)))
				if res.SecretDeleted {
					printDim("That was the last recipient, so the secret was deleted.")
					return nil
				}
			}
			return nil
		},
	}

	cmd.Flags().VarP(&emailList{&recipientEmails}, "to", "t", "Recipient `email` to revoke, repeatable or comma-separated")
	setGroup(cmd.Flags(), groupRecipients, "to")
	_ = cmd.MarkFlagRequired("to")
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
		Args: idArgs(1, "secret ID"),
		RunE: func(cmd *cobra.Command, args []string) error {
			secretID := args[0]

			c, err := newAuthenticatedClient()
			if err != nil {
				return err
			}

			update := sdk.PolicyUpdate{}
			hasChanges := false

			if cmd.Flags().Changed("ttl") {
				secs := int(ttlSeconds(ttl))
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
				return fmt.Errorf("nothing to change: give --ttl, --ip, --clear-ttl or --clear-ips")
			}

			updated, err := c.UpdatePolicy(secretID, update)
			switch {
			case errors.Is(err, api.ErrNotFound):
				return secretError(err, secretID)
			case errors.Is(err, api.ErrForbidden):
				return fmt.Errorf("only the sender of secret %s can change its policies", shortID(secretID))
			case err != nil:
				return fmt.Errorf("could not update the policies of secret %s: %w", shortID(secretID), apiCause(err))
			}
			api.Module(logger, "policy").Info("policies updated", "secret_id", updated.ID, "ttl_changed", update.TTLSeconds != nil, "ips_changed", update.AllowedIPs != nil)

			printSuccess(fmt.Sprintf("Updated the policies of secret %s (%s).", shortID(updated.ID), safe(updated.Name)))
			fmt.Fprintln(os.Stderr)
			if updated.ExpiresAt != nil {
				printKeyValue("TTL", "expires "+safe(*updated.ExpiresAt))
			} else {
				printKeyValue("TTL", "none")
			}
			if len(updated.AllowedIPs) > 0 {
				printKeyValue("IP Lock", safe(strings.Join(updated.AllowedIPs, ", ")))
			} else {
				printKeyValue("IP Lock", "none")
			}
			fmt.Fprintln(os.Stderr)

			return nil
		},
	}

	f := cmd.Flags()
	f.Var(&ttlFlag{&ttl}, "ttl", "Expire the secret this long from now: 2m to 365d, like 30m, 24h or 7d")
	f.Var(&ipList{&allowedIPs}, "ip", "Allow access only from these IP addresses or CIDR ranges, replacing the current list (at most 50)")
	f.BoolVar(&clearTTL, "clear-ttl", false, "Remove the TTL")
	f.BoolVar(&clearIPs, "clear-ips", false, "Remove the IP lock")
	setGroup(f, groupPolicies, "ttl", "ip", "clear-ttl", "clear-ips")
	cmd.MarkFlagsMutuallyExclusive("ttl", "clear-ttl")
	cmd.MarkFlagsMutuallyExclusive("ip", "clear-ips")
	cmd.MarkFlagsOneRequired("ttl", "ip", "clear-ttl", "clear-ips")

	return cmd
}

// --- shared helpers ---

// secretError is err, from fetching secret id, as the user reads it: a
// secret not found, or not shared with them, says so plainly.
func secretError(err error, id string) error {
	switch {
	case errors.Is(err, api.ErrNotFound):
		return withDetail(fmt.Errorf("secret %s not found", shortID(id)),
			"No secret with this ID is shared with you: it may have been deleted, or have expired. Check the ID with 'secret list'.")
	case errors.Is(err, api.ErrForbidden):
		return withDetail(fmt.Errorf("secret %s is not shared with you", shortID(id)),
			"Only its sender and recipients can see it. Check the ID with 'secret list'.")
	}
	return fmt.Errorf("could not fetch secret %s: %w", shortID(id), apiCause(err))
}

// recipientsSummary renders a recipient list for a table cell: the first
// email, and how many more there are.
func recipientsSummary(rs []sdk.SecretRecipient) string {
	switch len(rs) {
	case 0:
		return "-"
	case 1:
		return ellipsis(rs[0].Email, 25)
	default:
		return fmt.Sprintf("%s +%d", ellipsis(rs[0].Email, 20), len(rs)-1)
	}
}

// ellipsis shortens s to max characters for a table column, through safe:
// what it shortens comes from the server.
func ellipsis(s string, max int) string {
	r := []rune(safe(s))
	if len(r) <= max {
		return string(r)
	}
	return string(r[:max-3]) + "..."
}

// isArchivedRevision reports whether the revision was sent as a single
// tar.zst archive bundling multiple files. The compression label is the
// canonical signal: it's set to "tar+zstd" only by the archive code path.
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
// archive hides per-file metadata), so render that as "archived (entries
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

// formatBytes writes b in binary units, named as such (KiB, MiB, GiB), as
// the logs and the web app name them.
func formatBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// fingerprintWithStatus annotates an identity fingerprint with its trust
// status for inline display in revision details. Mirrors the colored
// indicator in the web UI:
//
//	primary   → green   "(primary identity)"
//	secondary → cyan    "(non-primary identity)"
//	invalid   → red     "(identity deleted)"
//
// When the fingerprint is empty or the status is unset, returns the
// fingerprint as-is so the details surface degrades gracefully.
func fingerprintWithStatus(fp string, status *string) string {
	fp = safe(fp)
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
