// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"bytes"
	"context"
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
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/deepsecret-io/deepsecret-go/apierror"
	"github.com/deepsecret-io/deepsecret-go/secrets"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/deepsecret-io/cli/internal/auth"
	"github.com/deepsecret-io/cli/internal/console"
	"github.com/deepsecret-io/cli/internal/errs"
	"github.com/deepsecret-io/cli/internal/flags"
	"github.com/deepsecret-io/cli/internal/identity"
	"github.com/deepsecret-io/cli/internal/logging"
	"github.com/deepsecret-io/cli/internal/ui"
)

// outputFormatted prints data as JSON or YAML to stdout. Returns true if it handled output.
func outputFormatted(format string, data any) (bool, error) {
	out, err := formatStructured(format, data, console.StdoutIsTerminal)
	if out == nil || err != nil {
		return false, err
	}
	if _, err := os.Stdout.Write(out); err != nil {
		return true, fmt.Errorf("could not write to stdout: %w", err)
	}
	return true, nil
}

// formatStructured is data as JSON or YAML, and nil for any other format.
// Redirected to a file or a pipe it is what the encoder wrote, byte for
// byte. On a terminal, the characters in it that would act on the terminal
// or reorder what is read (actsOnTerminal) are written as \u escapes, which
// JSON and YAML read back as the same characters: the values come from the
// server and from senders, and neither encoder escapes them all.
func formatStructured(format string, data any, terminal bool) ([]byte, error) {
	switch format {
	case "json":
		out, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return nil, err
		}
		out = append(out, '\n')
		// JSON holds such a character only inside a string, where an
		// escape stands for it.
		if terminal && bytes.ContainsFunc(out, actsOnTerminal) {
			out = escapeRunes(out, func(r rune) string {
				if r > 0xFFFF {
					hi, lo := utf16.EncodeRune(r)
					return fmt.Sprintf("\\u%04x\\u%04x", hi, lo)
				}
				return fmt.Sprintf("\\u%04x", r)
			})
		}
		return out, nil
	case "yaml":
		out, err := yaml.Marshal(data)
		if err != nil {
			return nil, err
		}
		if !terminal || !bytes.ContainsFunc(out, actsOnTerminal) {
			return out, nil
		}
		// YAML reads an escape only in a double-quoted scalar, so every
		// scalar that holds such a character is written as one first.
		var doc yaml.Node
		if err := doc.Encode(data); err != nil {
			return nil, err
		}
		quoteUnsafeScalars(&doc)
		if out, err = yaml.Marshal(&doc); err != nil {
			return nil, err
		}
		return escapeRunes(out, func(r rune) string {
			if r > 0xFFFF {
				return fmt.Sprintf("\\U%08x", r)
			}
			return fmt.Sprintf("\\u%04x", r)
		}), nil
	default:
		return nil, nil
	}
}

// actsOnTerminal reports a character that JSON or YAML output can hold raw
// and that a terminal acts on or that reorders what is read: DEL, a C1
// control such as U+009B, which starts a terminal command as ESC [ does,
// and an invisible formatting mark such as a right-to-left override. It is
// what console.Safe replaces, less the controls below U+0080 that both
// encoders escape themselves or use to lay the output out.
func actsOnTerminal(r rune) bool {
	return (r >= 0x7f && unicode.IsControl(r)) || (unicode.Is(unicode.Cf, r) && r != '\u200d')
}

// escapeRunes is b with every actsOnTerminal character replaced by what
// escape gives for it.
func escapeRunes(b []byte, escape func(rune) string) []byte {
	var out bytes.Buffer
	for len(b) > 0 {
		r, n := utf8.DecodeRune(b)
		if actsOnTerminal(r) {
			out.WriteString(escape(r))
		} else {
			out.Write(b[:n])
		}
		b = b[n:]
	}
	return out.Bytes()
}

// quoteUnsafeScalars makes every scalar under n that holds an
// actsOnTerminal character a double-quoted one, map keys included.
func quoteUnsafeScalars(n *yaml.Node) {
	if n.Kind == yaml.ScalarNode && strings.ContainsFunc(n.Value, actsOnTerminal) {
		n.Style = yaml.DoubleQuotedStyle
	}
	for _, c := range n.Content {
		quoteUnsafeScalars(c)
	}
}

// --- list ---

// The server gives a list a page at a time, at most listPageSize secrets a
// page. listAll asks for pages until it has them all, and stops at
// listMaxSecrets so a list of any length cannot exhaust memory.
const (
	listPageSize   = 100
	listMaxSecrets = 10000
)

// listAll returns every secret of a list, sent or received (fetch), with
// the email filter given, by asking for its pages in turn. It stops when
// the server's total is reached or a page comes back empty, so it ends
// whatever page size the server applies.
func listAll(ctx context.Context, fetch func(context.Context, ...secrets.ListOptions) ([]secrets.Info, int, error), email string) ([]secrets.Info, error) {
	var all []secrets.Info
	for len(all) < listMaxSecrets {
		page, total, err := fetch(ctx, secrets.ListOptions{Limit: listPageSize, Offset: len(all), Email: email})
		if err != nil {
			return nil, err
		}
		all = append(all, page...)
		if len(page) == 0 || len(all) >= total {
			break
		}
	}
	return all, nil
}

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
		RunE: func(cmd *cobra.Command, _ []string) error {
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

			c, err := auth.NewAuthenticatedClient()
			if err != nil {
				return err
			}

			// The inbox merges two lists and Sent leaves out the secrets
			// sent only to oneself, so server-side pagination would over-
			// or under-count: fetch every page and slice locally.
			var secretsList []secrets.Info
			if sent {
				all, err := listAll(cmd.Context(), c.Secrets.ListSent, toEmail)
				if err != nil {
					return fmt.Errorf("could not list your sent secrets: %w", errs.APICause(err))
				}
				secretsList = sentSecrets(all)
			} else {
				received, err := listAll(cmd.Context(), c.Secrets.ListReceived, fromEmail)
				if err != nil {
					return fmt.Errorf("could not list your inbox: %w", errs.APICause(err))
				}
				own, err := listAll(cmd.Context(), c.Secrets.ListSent, "")
				if err != nil {
					return fmt.Errorf("could not list your inbox: %w", errs.APICause(err))
				}
				secretsList = inboxSecrets(received, own, fromEmail)
			}

			total := len(secretsList)
			offset, end := 0, total
			if !noPagination {
				offset, end = pageBounds(total, page, limit)
			}
			secretsList = secretsList[offset:end]
			logging.Module(logging.Log, "secret").Debug("secrets listed", "view", view, "filter", filterEmail, "total", total, "shown", len(secretsList))

			if handled, err := outputFormatted(outputFmt, map[string]any{"secrets": secretsList, "total": total}); handled || err != nil {
				return err
			}

			if total == 0 {
				ui.Dimmed(emptyListMessage(sent, filterEmail))
				return nil
			}
			pages := (total + limit - 1) / limit
			if len(secretsList) == 0 {
				return errs.WithDetail(fmt.Errorf("there is no page %d", page),
					fmt.Sprintf("At %d per page, the %d secret%s take %d page%s.", limit, total, ui.Plural(total), pages, ui.Plural(pages)))
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
			ui.Header(header)
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
				contact := ui.Ellipsis(s.SenderEmail, 25)
				if sent {
					contact = recipientsSummary(s.Recipients)
				}
				_, _ = fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%d\t%s\t%s\n",
					console.Safe(s.ID),
					contact,
					ui.Ellipsis(s.Name, listNameWidth),
					filesStr,
					s.RevisionCount,
					ui.FormatBytes(s.TotalSize),
					s.UpdatedAt.Local().Format("2006-01-02 15:04"),
				)
			}
			if err := w.Flush(); err != nil {
				return fmt.Errorf("could not write to stdout: %w", err)
			}

			fmt.Fprintln(os.Stderr)
			if !noPagination && end < total {
				ui.Dimmed(fmt.Sprintf("Page %d of %d. Show the next with: --page %d", page, pages, page+1))
				fmt.Fprintln(os.Stderr)
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.BoolVar(&sent, "sent", false, "List the secrets you sent to others (default: your inbox)")
	f.Var(flags.NewEmail(&fromEmail), "from", "Inbox secrets from this sender `email` only")
	f.Var(flags.NewEmail(&toEmail), "to", "With --sent, secrets sent to this recipient `email` only")
	flags.SetGroup(f, flags.GroupFilters, "sent", "from", "to")
	f.Var(flags.NewIntRange(&limit, 20, 1, 1000, ""), "limit", "Secrets per page: 1 to 1000")
	f.Var(flags.NewIntRange(&page, 1, 1, 1_000_000, ""), "page", "Page number, from 1")
	f.BoolVar(&noPagination, "no-pagination", false, "Show every secret on one page")
	flags.SetGroup(f, flags.GroupPagination, "limit", "page", "no-pagination")
	outputFmt = "table"
	f.Var(flags.NewEnum(&outputFmt, "table", "json", "yaml"), "format", "Output format")
	flags.SetGroup(f, flags.GroupOutput, "format")
	cmd.MarkFlagsMutuallyExclusive("no-pagination", "page")
	cmd.MarkFlagsMutuallyExclusive("no-pagination", "limit")
	return cmd
}

// listNameWidth is how much of a secret's name list shows: enough for a
// default name (defaultName) with its random suffix, which alone tells
// two sends without a name apart.
const listNameWidth = 30

// inboxSecrets merges the inbox, newest first: the secrets received,
// and the ones the caller sent only to themself. Those come from the
// sent list, which keeps one the caller dismissed as its recipient, so
// the received list's copies are left out to list each secret once. A
// sender filter keeps them only when it names the caller.
func inboxSecrets(received, sent []secrets.Info, fromEmail string) []secrets.Info {
	inbox := make([]secrets.Info, 0, len(received))
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
func sentSecrets(sent []secrets.Info) []secrets.Info {
	out := make([]secrets.Info, 0, len(sent))
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
		Args: flags.IDArgs(1, "secret ID"),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := auth.NewAuthenticatedClient()
			if err != nil {
				return err
			}

			secretID := args[0]
			detail, err := c.Secrets.DescribeFull(cmd.Context(), secretID)
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
				fmt.Fprintf(w, "%-30s%s\n", key+":", console.Safe(val))
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
					fmt.Fprintf(w, "  - %-26s%s\n", "Email:", console.Safe(r.Email))
					if r.Name != "" {
						fmt.Fprintf(w, "    %-26s%s\n", "Name:", console.Safe(r.Name))
					}
					fmt.Fprintf(w, "    %-26s%s\n", "ID:", console.Safe(r.ID))
				}
			}
			if s.DismissedAt != "" {
				kv("Dismissed At", displayTimeString(s.DismissedAt))
			}
			kv("Latest Revision ID", s.LatestRevisionID)
			kv("Revision Count", fmt.Sprintf("%d", s.RevisionCount))
			kv("Total Size", ui.FormatBytes(s.TotalSize))
			// When the secret was sent with --archive (or auto-archived), the
			// server stores FilesCount=0 by design: the archive hides
			// per-file metadata. Render that distinction instead of a bare 0
			// so the user understands "0" doesn't mean "no files".
			kv("Files Count", formatFilesCount(s.FilesCount, secretLatestArchived(detail, s.LatestRevisionID)))
			kv("Created At", displayTime(s.CreatedAt))
			kv("Updated At", displayTime(s.UpdatedAt))
			if s.ExpiresAt != "" {
				kv("Expires At", displayTimeString(s.ExpiresAt))
			}
			writeIPLock(w, s)

			// Revisions: same fields as JSON revisions[]
			if len(detail.Revisions) > 0 {
				var visible []secrets.RevisionInfo

				if revisionID != "" {
					for _, r := range detail.Revisions {
						if r.ID == revisionID {
							visible = append(visible, r)
							break
						}
					}
					if len(visible) == 0 {
						return errs.WithDetail(fmt.Errorf("revision %s not found in secret %s", ui.ShortID(revisionID), ui.ShortID(s.ID)),
							"List the revisions you can see with: secret describe "+console.Safe(s.ID)+" --all")
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
						fmt.Fprintf(w, "  %-28s%s\n", key+":", console.Safe(val))
					}
					ikv := func(key, val string) {
						fmt.Fprintf(w, "    %-30s%s\n", key+":", console.Safe(val))
					}

					rkv("ID", r.ID)
					rkv("Revision Number", fmt.Sprintf("%d", r.RevisionNumber))
					rkv("Size", ui.FormatBytes(r.Size))
					rkv("Files Count", formatFilesCount(r.FilesCount, isArchivedRevision(r)))
					if r.StorageName != "" {
						rkv("Storage Name", r.StorageName)
					}
					rkv("Created At", displayTimeString(r.CreatedAt))
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
							fmt.Fprintf(w, "      - %-26s%s\n", "Email:", console.Safe(rr.Email))
							fmt.Fprintf(w, "        %-26s%s\n", "Key Fingerprint:", fingerprintWithStatus(rr.KeyFingerprint, rr.KeyStatus))
						}
					}
					ikv("Checksum SHA256", r.Integrity.ChecksumSHA256)
					ikv("Etag", r.Integrity.Etag)
					writeFilesMeta(w, r.FilesMeta)
				}
			}

			_, err = io.WriteString(os.Stderr, b.String())
			return err
		},
	}

	f := cmd.Flags()
	f.BoolVar(&allRevisions, "all", false, "Show every revision")
	f.VarP(flags.NewUUID(&revisionID), "revision", "r", "Show this revision `id` (default: the latest)")
	flags.SetGroup(f, flags.GroupInput, "all", "revision")
	outputFmt = "table"
	f.Var(flags.NewEnum(&outputFmt, "table", "json", "yaml"), "format", "Output format")
	flags.SetGroup(f, flags.GroupOutput, "format")
	cmd.MarkFlagsMutuallyExclusive("all", "revision")
	cmd.AddCommand(newDescribeTeamCmd())
	return cmd
}

func newDescribeTeamCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "team <name>",
		Short: "Show a team's members (same as: secret teams describe <name>)",
		Args:  teamNameArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			return describeTeam(cmd.Context(), args[0])
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
		Args: flags.MinIDArgs(1, "secret ID"),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := auth.NewAuthenticatedClient()
			if err != nil {
				return err
			}

			// The server deletes only the secrets the caller sent, and
			// skips any other without saying so. Check each first, so the
			// command deletes all of them or none, and says which.
			ids := slices.Compact(slices.Sorted(slices.Values(args)))
			me, err := c.Identity.ResolveMemberID(cmd.Context())
			if err != nil {
				return fmt.Errorf("could not fetch your account: %w", errs.APICause(err))
			}
			for _, id := range ids {
				info, err := c.Secrets.Describe(cmd.Context(), id)
				if err != nil {
					return secretError(err, id)
				}
				if info.SenderID != me {
					return errs.WithDetail(fmt.Errorf("you did not send secret %s, so you cannot delete it", ui.ShortID(id)),
						"Only a secret's sender can delete it. Nothing was deleted.")
				}
			}

			if err := c.Secrets.Delete(cmd.Context(), ids...); err != nil {
				return fmt.Errorf("could not delete the secret%s: %w", ui.Plural(len(ids)), errs.APICause(err))
			}
			logging.Module(logging.Log, "secret").Info("secrets deleted", "ids", ids)

			ui.Success(fmt.Sprintf("Deleted %d secret%s.", len(ids), ui.Plural(len(ids))))
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
		Args: flags.IDArgs(1, "secret ID"),
		RunE: func(cmd *cobra.Command, args []string) error {
			secretID := args[0]

			c, err := auth.NewAuthenticatedClient()
			if err != nil {
				return err
			}

			for _, email := range recipientEmails {
				// A 404 here is the secret's or the recipient's access, so
				// the server's message says which.
				res, err := c.Secrets.RevokeRecipient(cmd.Context(), secretID, email)
				switch {
				case errors.Is(err, apierror.ErrForbidden):
					return fmt.Errorf("only the sender of secret %s can revoke its recipients", ui.ShortID(secretID))
				case err != nil:
					return fmt.Errorf("could not revoke %s: %w", email, errs.APICause(err))
				}
				logging.Module(logging.Log, "secret").Info("recipient revoked", "secret_id", secretID, "email", res.Email, "secret_deleted", res.SecretDeleted)
				ui.Success(fmt.Sprintf("Revoked %s.", console.Safe(res.Email)))
				if res.SecretDeleted {
					ui.Dimmed("That was the last recipient, so the secret was deleted.")
					return nil
				}
			}
			return nil
		},
	}

	cmd.Flags().VarP(flags.NewEmailList(&recipientEmails), "to", "t", "Recipient `email` to revoke, repeatable or comma-separated")
	flags.SetGroup(cmd.Flags(), flags.GroupRecipients, "to")
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
		Args: flags.IDArgs(1, "secret ID"),
		RunE: func(cmd *cobra.Command, args []string) error {
			secretID := args[0]

			c, err := auth.NewAuthenticatedClient()
			if err != nil {
				return err
			}

			update := secrets.PolicyUpdate{}
			hasChanges := false

			if cmd.Flags().Changed("ttl") {
				secs := int(flags.TTLSeconds(ttl))
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

			updated, err := c.Secrets.UpdatePolicy(cmd.Context(), secretID, update)
			switch {
			case errors.Is(err, apierror.ErrNotFound):
				return secretError(err, secretID)
			case errors.Is(err, apierror.ErrForbidden):
				return fmt.Errorf("only the sender of secret %s can change its policies", ui.ShortID(secretID))
			case err != nil:
				return fmt.Errorf("could not update the policies of secret %s: %w", ui.ShortID(secretID), errs.APICause(err))
			}
			logging.Module(logging.Log, "policy").Info("policies updated", "secret_id", updated.ID, "ttl_changed", update.TTLSeconds != nil, "ips_changed", update.AllowedIPs != nil)

			ui.Success(fmt.Sprintf("Updated the policies of secret %s (%s).", ui.ShortID(updated.ID), console.Safe(updated.Name)))
			fmt.Fprintln(os.Stderr)
			printPolicies(updated)
			fmt.Fprintln(os.Stderr)

			return nil
		},
	}

	f := cmd.Flags()
	f.Var(flags.NewTTL(&ttl), "ttl", "Expire the secret this long from now: 2m to 365d, like 30m, 24h or 7d")
	f.Var(flags.NewIPList(&allowedIPs), "ip", "Allow access only from these IP addresses or CIDR ranges, replacing the current list (at most 50)")
	f.BoolVar(&clearTTL, "clear-ttl", false, "Remove the TTL")
	f.BoolVar(&clearIPs, "clear-ips", false, "Remove the IP lock")
	flags.SetGroup(f, flags.GroupPolicies, "ttl", "ip", "clear-ttl", "clear-ips")
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
	case errors.Is(err, apierror.ErrNotFound):
		return errs.WithDetail(fmt.Errorf("secret %s not found", ui.ShortID(id)),
			"No secret with this ID is shared with you: it may have been deleted, or have expired. Check the ID with 'secret list'.")
	case errors.Is(err, apierror.ErrForbidden):
		return errs.WithDetail(fmt.Errorf("secret %s is not shared with you", ui.ShortID(id)),
			"Only its sender and recipients can see it. Check the ID with 'secret list'.")
	}
	return fmt.Errorf("could not fetch secret %s: %w", ui.ShortID(id), errs.APICause(err))
}

// recipientsSummary renders a recipient list for a table cell: the first
// email, and how many more there are.
func recipientsSummary(rs []secrets.SecretRecipient) string {
	switch len(rs) {
	case 0:
		return "-"
	case 1:
		return ui.Ellipsis(rs[0].Email, 25)
	default:
		return fmt.Sprintf("%s +%d", ui.Ellipsis(rs[0].Email, 20), len(rs)-1)
	}
}

// ipLockOrgEnforced is the API's ip_lock_source for an IP lock that the
// secret's organization enforces.
const ipLockOrgEnforced = "org-enforced"

// ipLockSummary is how a secret's IP lock reads, or "" when it has none:
// the addresses its sender allowed, or, for a lock its organization
// enforces (source is the API's ip_lock_source), that there is one. The
// API shows the organization's addresses to its admins only, so allowed
// is then empty, and would read as no lock.
func ipLockSummary(source string, allowed []string) string {
	if source == ipLockOrgEnforced {
		return "set by the organization (addresses not shown)"
	}
	return strings.Join(allowed, ", ")
}

// writeIPLock adds a secret's IP lock to describe, when it has one, under
// the name a send and policy give it.
func writeIPLock(w *strings.Builder, s secrets.Info) {
	if lock := ipLockSummary(s.IPLockSource, s.AllowedIPs); lock != "" {
		fmt.Fprintf(w, "%-30s%s\n", "IP Lock:", console.Safe(lock))
	}
}

// printPolicies shows a secret's policies after policy updated them: when
// it expires, and its IP lock, which is "none" only when no lock is in
// force.
func printPolicies(updated *secrets.PolicyResult) {
	if updated.ExpiresAt != nil {
		ui.KeyValue("TTL", "expires "+console.Safe(*updated.ExpiresAt))
	} else {
		ui.KeyValue("TTL", "none")
	}
	if lock := ipLockSummary(updated.IPLockSource, updated.AllowedIPs); lock != "" {
		ui.KeyValue("IP Lock", console.Safe(lock))
	} else {
		ui.KeyValue("IP Lock", "none")
	}
}

// writeFilesMeta lists, under a revision in describe, the files the server
// lists for it: their names and sizes. The server keeps no hash of a
// file's content; the hashes a decrypt shows come from the encrypted
// payload, once it is verified.
func writeFilesMeta(w *strings.Builder, files []secrets.FileMeta) {
	if len(files) == 0 {
		return
	}
	fmt.Fprintf(w, "  Files Meta:\n")
	for _, f := range files {
		fmt.Fprintf(w, "    - %-28s%s\n", "Name:", console.Safe(f.Name))
		fmt.Fprintf(w, "      %-28s%s\n", "Size:", ui.FormatBytes(f.Size))
	}
}

// isArchivedRevision reports whether the revision was sent as a single
// tar.zst archive bundling multiple files. The compression label is the
// canonical signal: it's set to "tar+zstd" only by the archive code path.
func isArchivedRevision(r secrets.RevisionInfo) bool {
	return r.Integrity.Compression == "tar+zstd"
}

// secretLatestArchived reports whether the secret's latest revision was
// sent archived. Returns false if the latest revision isn't loaded in the
// detail.
func secretLatestArchived(detail *secrets.Detail, latestRevisionID string) bool {
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
	note := identity.ProtectionNote(fp)
	fp = console.Safe(fp)
	if fp == "" || status == nil || *status == "" {
		return fp + note
	}
	switch *status {
	case "primary":
		return fp + " " + console.Green + "(primary identity)" + console.Reset + note
	case "secondary":
		return fp + " " + console.Cyan + "(non-primary identity)" + console.Reset + note
	case "invalid":
		return fp + " " + console.Red + "(identity deleted)" + console.Reset + note
	default:
		return fp + note
	}
}

// displayTime is t in the local zone, as decrypt shows the signing time.
func displayTime(t time.Time) string {
	return t.Local().Format("2006-01-02 15:04:05 MST")
}

// displayTimeString is displayTime for a time the API sent as text; text
// that is not a time is shown as it came.
func displayTimeString(s string) string {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return s
	}
	return displayTime(t)
}
