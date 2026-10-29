// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
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
		return fmt.Errorf("fetch account info: %w", err)
	}
	if info.OrgID == "" {
		return fmt.Errorf("you must be a member of an organization to describe groups")
	}

	groups, err := c.ListGroups(info.OrgID)
	if err != nil {
		return fmt.Errorf("list groups: %w", err)
	}

	wanted := strings.ToLower(name)
	var matched *sdk.GroupInfo
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
			return fmt.Errorf("group %q not found (no groups exist in this organization)", name)
		}
		return fmt.Errorf("group %q not found (available: %s)", name, strings.Join(available, ", "))
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
		return fmt.Errorf("write to stdout: %w", err)
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
				return fmt.Errorf("fetch account info: %w", err)
			}
			if info.OrgID == "" {
				return fmt.Errorf("you must be a member of an organization to list groups")
			}

			groups, err := c.ListGroups(info.OrgID)
			if err != nil {
				return fmt.Errorf("list groups: %w", err)
			}

			if len(groups) == 0 {
				printDim("No groups in this organization.")
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
				return fmt.Errorf("write to stdout: %w", err)
			}
			fmt.Fprintln(os.Stderr)
			return nil
		},
	}
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
