// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	deepsecret "github.com/deepsecret-io/deepsecret-go"
	sdkidentity "github.com/deepsecret-io/deepsecret-go/identity"
	"github.com/spf13/cobra"

	"github.com/deepsecret-io/cli/internal/auth"
	"github.com/deepsecret-io/cli/internal/console"
	"github.com/deepsecret-io/cli/internal/errs"
	"github.com/deepsecret-io/cli/internal/ui"
)

func newGroupsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "groups",
		Short: "List and inspect organization groups",
	}
	cmd.AddCommand(newGroupsListCmd(), newGroupsDescribeCmd())
	return cmd
}

func newGroupsDescribeCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "describe <name>",
		Aliases: []string{"desc", "show"},
		Short:   "Show a group's members (alias: desc, show)",
		Args:    groupNameArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			return describeGroup(cmd.Context(), args[0])
		},
	}
}

// describeGroup looks up a group by name in the caller's primary org and
// prints its members. Used by both `secret groups describe <name>` and
// `secret describe group <name>`.
func describeGroup(ctx context.Context, name string) error {
	c, err := auth.NewAuthenticatedClient()
	if err != nil {
		return err
	}

	info, err := c.Identity.WhoAmI(ctx)
	if err != nil {
		return fmt.Errorf("could not fetch your account: %w", errs.APICause(err))
	}
	matched, err := findGroup(ctx, c, info, name)
	if err != nil {
		return err
	}

	ui.Header(fmt.Sprintf("Group: %s", matched.Name))
	fmt.Fprintln(os.Stderr)
	ui.KeyValue("ID", console.Safe(matched.ID))
	ui.KeyValue("Members", fmt.Sprintf("%d", len(matched.Members)))
	fmt.Fprintln(os.Stderr)

	if len(matched.Members) == 0 {
		ui.Dimmed("No members in this group.")
		return nil
	}

	members := make([]sdkidentity.GroupMember, len(matched.Members))
	copy(members, matched.Members)
	sort.Slice(members, func(i, j int) bool { return members[i].Email < members[j].Email })

	// Rows wait in the tabwriter until Flush, which returns any write error.
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintf(w, "  EMAIL\tNAME\tROLE\n")
	_, _ = fmt.Fprintf(w, "  -----\t----\t----\n")
	for _, m := range members {
		fullName := strings.TrimSpace(m.FirstName + " " + m.LastName)
		if fullName == "" {
			fullName = "-"
		}
		role := m.Role
		if role == "" {
			role = "-"
		}
		_, _ = fmt.Fprintf(w, "  %s\t%s\t%s\n", console.Safe(m.Email), console.Safe(fullName), console.Safe(role))
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("could not write to stdout: %w", err)
	}
	fmt.Fprintln(os.Stderr)
	return nil
}

func newGroupsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List the groups you can send to (alias: ls)",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := auth.NewAuthenticatedClient()
			if err != nil {
				return err
			}

			info, err := c.Identity.WhoAmI(cmd.Context())
			if err != nil {
				return fmt.Errorf("could not fetch your account: %w", errs.APICause(err))
			}
			groups, all, err := orgGroups(cmd.Context(), c, info)
			if err != nil {
				return err
			}

			if len(groups) == 0 {
				ui.Dimmed(noGroups(all))
				return nil
			}

			sort.Slice(groups, func(i, j int) bool { return groups[i].Name < groups[j].Name })

			title := "Groups"
			if !all {
				title = "Your groups"
			}
			ui.Header(fmt.Sprintf("%s (%d)", title, len(groups)))
			fmt.Fprintln(os.Stderr)

			// Rows wait in the tabwriter until Flush, which returns any write error.
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintf(w, "  NAME\tMEMBERS\tID\n")
			_, _ = fmt.Fprintf(w, "  ----\t-------\t--\n")
			for _, g := range groups {
				_, _ = fmt.Fprintf(w, "  %s\t%d\t%s\n", console.Safe(g.Name), len(g.Members), console.Safe(g.ID))
			}
			if err := w.Flush(); err != nil {
				return fmt.Errorf("could not write to stdout: %w", err)
			}
			fmt.Fprintln(os.Stderr)
			return nil
		},
	}
}

// orgGroups lists the groups the account info describes can send to: every
// group of its organization for an owner or admin, and the groups they
// belong to for a member. The server's "groups" permission says which, and
// all reports it.
func orgGroups(ctx context.Context, c *deepsecret.Client, info *sdkidentity.Actor) (groups []sdkidentity.Group, all bool, err error) {
	if info.OrgID == "" {
		return nil, false, errors.New("your account is not in an organization, so it has no groups")
	}
	if info.Permissions["groups"] {
		groups, err = c.Identity.ListGroups(ctx, info.OrgID)
		if err != nil {
			return nil, true, fmt.Errorf("could not list your organization's groups: %w", errs.APICause(err))
		}
		return groups, true, nil
	}
	groups, err = c.Identity.ListMyGroups(ctx, info.OrgID)
	if err != nil {
		return nil, false, fmt.Errorf("could not list your groups: %w", errs.APICause(err))
	}
	return groups, false, nil
}

// findGroup finds the group named name, in any case, among the groups the
// account info describes can send to. For a member, a group they are not
// in is not found, like one that does not exist.
func findGroup(ctx context.Context, c *deepsecret.Client, info *sdkidentity.Actor, name string) (*sdkidentity.Group, error) {
	groups, all, err := orgGroups(ctx, c, info)
	if err != nil {
		return nil, err
	}
	for i := range groups {
		if strings.EqualFold(groups[i].Name, name) {
			return &groups[i], nil
		}
	}
	return nil, errs.WithDetail(fmt.Errorf("group %q not found", name), groupNames(groups, all))
}

// groupNames names the groups that were searched, for the error of a group
// not found among them: the organization's, or the caller's own.
func groupNames(groups []sdkidentity.Group, all bool) string {
	if len(groups) == 0 {
		return noGroups(all)
	}
	names := make([]string, len(groups))
	for i, g := range groups {
		names[i] = console.Safe(g.Name)
	}
	sort.Strings(names)
	if !all {
		return "The groups you belong to: " + strings.Join(names, ", ") + "."
	}
	return "Your organization's groups: " + strings.Join(names, ", ") + "."
}

// noGroups says there is no group to list: none in the organization, or
// none the caller belongs to.
func noGroups(all bool) string {
	if all {
		return "Your organization has no groups yet."
	}
	return "You belong to no group yet. Your organization's owner or an admin adds members to groups."
}

// groupNameArg accepts exactly one group name that is not blank.
func groupNameArg(cmd *cobra.Command, args []string) error {
	if err := cobra.ExactArgs(1)(cmd, args); err != nil {
		return err
	}
	if args[0] = strings.TrimSpace(args[0]); args[0] == "" {
		return fmt.Errorf("the group name is blank")
	}
	return nil
}
