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

func newTeamsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "teams",
		Short: "List and inspect organization teams",
	}
	cmd.AddCommand(newTeamsListCmd(), newTeamsDescribeCmd())
	return cmd
}

func newTeamsDescribeCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "describe <name>",
		Aliases: []string{"desc", "show"},
		Short:   "Show a team's members (alias: desc, show)",
		Args:    teamNameArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			return describeTeam(cmd.Context(), args[0])
		},
	}
}

// describeTeam looks up a team by name in the caller's primary org and
// prints its members. Used by both `secret teams describe <name>` and
// `secret describe team <name>`.
func describeTeam(ctx context.Context, name string) error {
	c, err := auth.NewAuthenticatedClient()
	if err != nil {
		return err
	}

	info, err := c.Identity.WhoAmI(ctx)
	if err != nil {
		return fmt.Errorf("could not fetch your account: %w", errs.APICause(err))
	}
	matched, err := findTeam(ctx, c, info, name)
	if err != nil {
		return err
	}

	ui.Header(fmt.Sprintf("Team: %s", matched.Name))
	fmt.Fprintln(os.Stderr)
	ui.KeyValue("ID", console.Safe(matched.ID))
	ui.KeyValue("Members", fmt.Sprintf("%d", len(matched.Members)))
	fmt.Fprintln(os.Stderr)

	if len(matched.Members) == 0 {
		ui.Dimmed("No members in this team.")
		return nil
	}

	members := make([]sdkidentity.TeamMember, len(matched.Members))
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

func newTeamsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List the teams you can send to (alias: ls)",
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
			teams, all, err := orgTeams(cmd.Context(), c, info)
			if err != nil {
				return err
			}

			if len(teams) == 0 {
				ui.Dimmed(noTeams(all))
				return nil
			}

			sort.Slice(teams, func(i, j int) bool { return teams[i].Name < teams[j].Name })

			title := "Teams"
			if !all {
				title = "Your teams"
			}
			ui.Header(fmt.Sprintf("%s (%d)", title, len(teams)))
			fmt.Fprintln(os.Stderr)

			// Rows wait in the tabwriter until Flush, which returns any write error.
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintf(w, "  NAME\tMEMBERS\tID\n")
			_, _ = fmt.Fprintf(w, "  ----\t-------\t--\n")
			for _, tm := range teams {
				_, _ = fmt.Fprintf(w, "  %s\t%d\t%s\n", console.Safe(tm.Name), len(tm.Members), console.Safe(tm.ID))
			}
			if err := w.Flush(); err != nil {
				return fmt.Errorf("could not write to stdout: %w", err)
			}
			fmt.Fprintln(os.Stderr)
			return nil
		},
	}
}

// orgTeams lists the teams the account info describes can send to: every
// team of its organization for an owner or admin, and the teams they
// belong to for a member. The server's "teams" permission says which, and
// all reports it.
func orgTeams(ctx context.Context, c *deepsecret.Client, info *sdkidentity.Member) (teams []sdkidentity.Team, all bool, err error) {
	if info.OrgID == "" {
		return nil, false, errors.New("your account is not in an organization, so it has no teams")
	}
	if info.Permissions["teams"] {
		teams, err = c.Identity.ListTeams(ctx, info.OrgID)
		if err != nil {
			return nil, true, fmt.Errorf("could not list your organization's teams: %w", errs.APICause(err))
		}
		return teams, true, nil
	}
	teams, err = c.Identity.ListMyTeams(ctx, info.OrgID)
	if err != nil {
		return nil, false, fmt.Errorf("could not list your teams: %w", errs.APICause(err))
	}
	return teams, false, nil
}

// teamRecipients is who a team send goes to: everyone in the team, the
// sender included when they are in it, so a team of one sends to its only
// member. An entry with no address is skipped, and a team with nobody to
// send to is refused.
func teamRecipients(team *sdkidentity.Team) ([]string, error) {
	var recipients []string
	for _, m := range team.Members {
		if m.Email != "" {
			recipients = append(recipients, m.Email)
		}
	}
	if len(recipients) == 0 {
		return nil, errs.WithDetail(fmt.Errorf("team %q has no members to send to", team.Name),
			"Add a member to the team, or leave out --team to send the secret to yourself.")
	}
	return recipients, nil
}

// findTeam finds the team named name, in any case, among the teams the
// account info describes can send to. For a member, a team they are not
// in is not found, like one that does not exist.
func findTeam(ctx context.Context, c *deepsecret.Client, info *sdkidentity.Member, name string) (*sdkidentity.Team, error) {
	teams, all, err := orgTeams(ctx, c, info)
	if err != nil {
		return nil, err
	}
	for i := range teams {
		if strings.EqualFold(teams[i].Name, name) {
			return &teams[i], nil
		}
	}
	return nil, errs.WithDetail(fmt.Errorf("team %q not found", name), teamNames(teams, all))
}

// teamNames names the teams that were searched, for the error of a team
// not found among them: the organization's, or the caller's own.
func teamNames(teams []sdkidentity.Team, all bool) string {
	if len(teams) == 0 {
		return noTeams(all)
	}
	names := make([]string, len(teams))
	for i, tm := range teams {
		names[i] = console.Safe(tm.Name)
	}
	sort.Strings(names)
	if !all {
		return "The teams you belong to: " + strings.Join(names, ", ") + "."
	}
	return "Your organization's teams: " + strings.Join(names, ", ") + "."
}

// noTeams says there is no team to list: none in the organization, or
// none the caller belongs to.
func noTeams(all bool) string {
	if all {
		return "Your organization has no teams yet."
	}
	return "You belong to no team yet. Your organization's owner or an admin adds members to teams."
}

// teamNameArg accepts exactly one team name that is not blank.
func teamNameArg(cmd *cobra.Command, args []string) error {
	if err := cobra.ExactArgs(1)(cmd, args); err != nil {
		return err
	}
	if args[0] = strings.TrimSpace(args[0]); args[0] == "" {
		return fmt.Errorf("the team name is blank")
	}
	return nil
}
