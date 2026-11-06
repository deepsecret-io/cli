// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/deepsecret-io/sdk"
	"github.com/spf13/cobra"

	"github.com/deepsecret-io/cli/internal/auth"
	"github.com/deepsecret-io/cli/internal/console"
	"github.com/deepsecret-io/cli/internal/errs"
	"github.com/deepsecret-io/cli/internal/identity"
	"github.com/deepsecret-io/cli/internal/ui"
)

func newWhoamiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Show the account you are signed in as",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := auth.NewAuthenticatedClient()
			if err != nil {
				return err
			}

			var actor sdk.ActorInfo
			var keys []sdk.RemoteKey
			steps := []ui.Step{
				{
					Label: "Fetching your account",
					Done:  "Account fetched",
					Action: func() (string, error) {
						info, err := c.WhoAmI(cmd.Context())
						if err != nil {
							return "", fmt.Errorf("could not fetch your account: %w", errs.APICause(err))
						}
						actor = *info
						return "email=" + actor.Email, nil
					},
				},
				registeredKeysStep(listRemoteKeysOf(cmd.Context(), c), &keys),
			}
			if err := ui.RunPipeline(cmd.Context(), "account", steps); err != nil {
				return err
			}

			fmt.Fprintln(os.Stderr)
			ui.KeyValue("ID", console.Safe(actor.ID))
			ui.KeyValue("Email", console.Safe(actor.Email))
			ui.KeyValue("Name", console.Safe(orDefault(actor.Name, "not set")))
			ui.KeyValue("Plan", console.Safe(orDefault(actor.TierName, "none")))
			ui.KeyValue("Status", console.Safe(subscriptionStatus(actor.SubscriptionStatus, actor.Subscription.TrialEndsAt, time.Now())))
			ui.KeyValue("Primary key", primaryKeyLabel(keys))
			fmt.Fprintln(os.Stderr)
			return nil
		},
	}
}

// listRemoteKeysOf is c's registered keys, as registeredKeysStep lists them.
func listRemoteKeysOf(ctx context.Context, c *sdk.Client) func() ([]sdk.RemoteKey, error) {
	return func() ([]sdk.RemoteKey, error) { return c.ListRemoteKeys(ctx) }
}

// registeredKeysStep is the step that fetches, with list, the keys
// registered for the account into keys. A failure fails the step: no keys
// fetched is not the same as no keys registered.
func registeredKeysStep(list func() ([]sdk.RemoteKey, error), keys *[]sdk.RemoteKey) ui.Step {
	return ui.Step{
		Label: "Fetching your registered keys",
		Done:  "Registered keys fetched",
		Action: func() (string, error) {
			got, err := list()
			if err != nil {
				return "", fmt.Errorf("could not list your registered keys: %w", errs.APICause(err))
			}
			*keys = got
			return fmt.Sprintf("keys=%d", len(got)), nil
		},
	}
}

// primaryKeyLabel is the Primary key line of whoami: the fingerprint of the
// primary among keys, or why there is none.
func primaryKeyLabel(keys []sdk.RemoteKey) string {
	for _, k := range keys {
		if k.IsPrimary {
			if l := identity.RemoteLabel(k); l != "" {
				return console.Safe(k.Fingerprint) + " (" + l + ")"
			}
			return console.Safe(k.Fingerprint)
		}
	}
	if len(keys) == 0 {
		return "none registered (create one with: secret identity generate)"
	}
	return "none set (choose one with: secret identity set-primary <fingerprint>)"
}

// orDefault is s, or def when s is empty.
func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// subscriptionStatus describes the subscription status for whoami and
// doctor, in words. Without a subscription it shows the free trial and
// when it ends, or when it ended: the API reports "inactive" during a
// trial, which gives access.
func subscriptionStatus(status string, trialEndsAt *string, now time.Time) string {
	status = orDefault(strings.ReplaceAll(status, "_", " "), "none")
	if status == "active" || trialEndsAt == nil {
		return status
	}
	ends, err := time.Parse(time.RFC3339, *trialEndsAt)
	if err != nil {
		return status
	}
	if now.Before(ends) {
		return "free trial, ends " + ends.Local().Format("2 Jan 2006 15:04")
	}
	return status + ", free trial ended " + ends.Local().Format("2 Jan 2006")
}
