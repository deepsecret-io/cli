// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/deepsecret-io/sdk"
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
			return describeGroup(args[0])
		},
	}
}

// describeGroup looks up a group by name in the caller's primary org and
// prints its members. Used by both `secret groups describe <name>` and
// `secret describe group <name>`.
func describeGroup(name string) error {
	c, err := newAuthenticatedClient()
	if err != nil {
		return err
	}

	info, err := c.WhoAmI()
	if err != nil {
		return fmt.Errorf("could not fetch your account: %w", apiCause(err))
	}
	matched, err := findGroup(c, info, name)
	if err != nil {
		return err
	}

	printHeader(fmt.Sprintf("Group: %s", matched.Name))
	fmt.Fprintln(os.Stderr)
	printKeyValue("ID", safe(matched.ID))
	printKeyValue("Members", fmt.Sprintf("%d", len(matched.Members)))
	fmt.Fprintln(os.Stderr)

	if len(matched.Members) == 0 {
		printDim("No members in this group.")
		return nil
	}

	members := make([]sdk.GroupMemberInfo, len(matched.Members))
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
		_, _ = fmt.Fprintf(w, "  %s\t%s\t%s\n", safe(m.Email), safe(fullName), safe(role))
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
		Short:   "List groups in your organization (alias: ls)",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newAuthenticatedClient()
			if err != nil {
				return err
			}

			info, err := c.WhoAmI()
			if err != nil {
				return fmt.Errorf("could not fetch your account: %w", apiCause(err))
			}
			groups, err := orgGroups(c, info)
			if err != nil {
				return err
			}

			if len(groups) == 0 {
				printDim("Your organization has no groups yet.")
				return nil
			}

			sort.Slice(groups, func(i, j int) bool { return groups[i].Name < groups[j].Name })

			printHeader(fmt.Sprintf("Groups (%d)", len(groups)))
			fmt.Fprintln(os.Stderr)

			// Rows wait in the tabwriter until Flush, which returns any write error.
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintf(w, "  NAME\tMEMBERS\tID\n")
			_, _ = fmt.Fprintf(w, "  ----\t-------\t--\n")
			for _, g := range groups {
				_, _ = fmt.Fprintf(w, "  %s\t%d\t%s\n", safe(g.Name), len(g.Members), safe(g.ID))
			}
			if err := w.Flush(); err != nil {
				return fmt.Errorf("could not write to stdout: %w", err)
			}
			fmt.Fprintln(os.Stderr)
			return nil
		},
	}
}

// orgGroups lists the groups of the organization of the account info
// describes.
func orgGroups(c *Client, info *sdk.ActorInfo) ([]sdk.GroupInfo, error) {
	if info.OrgID == "" {
		return nil, errors.New("your account is not in an organization, so it has no groups")
	}
	groups, err := c.ListGroups(info.OrgID)
	if err != nil {
		return nil, fmt.Errorf("could not list your organization's groups: %w", apiCause(err))
	}
	return groups, nil
}

// findGroup finds the group named name, in any case, in the organization
// of the account info describes.
func findGroup(c *Client, info *sdk.ActorInfo, name string) (*sdk.GroupInfo, error) {
	groups, err := orgGroups(c, info)
	if err != nil {
		return nil, err
	}
	for i := range groups {
		if strings.EqualFold(groups[i].Name, name) {
			return &groups[i], nil
		}
	}
	return nil, withDetail(fmt.Errorf("group %q not found", name), groupNames(groups))
}

// groupNames names an organization's groups, for the error of a group not
// found among them.
func groupNames(groups []sdk.GroupInfo) string {
	if len(groups) == 0 {
		return "Your organization has no groups yet."
	}
	names := make([]string, len(groups))
	for i, g := range groups {
		names[i] = safe(g.Name)
	}
	sort.Strings(names)
	return "Your organization's groups: " + strings.Join(names, ", ") + "."
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
