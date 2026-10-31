// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/deepsecret-io/sdk"
)

func newWhoamiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Show the account you are signed in as",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newAuthenticatedClient()
			if err != nil {
				return err
			}

			var actor sdk.ActorInfo
			var keys []sdk.RemoteKey
			steps := []step{
				{
					label: "Fetching your account",
					done:  "Account fetched",
					action: func() (string, error) {
						info, err := c.WhoAmI()
						if err != nil {
							return "", fmt.Errorf("could not fetch your account: %w", apiCause(err))
						}
						actor = *info
						return "email=" + actor.Email, nil
					},
				},
				registeredKeysStep(c.ListRemoteKeys, &keys),
			}
			if err := runPipeline("account", steps); err != nil {
				return err
			}

			fmt.Fprintln(os.Stderr)
			printKeyValue("ID", safe(actor.ID))
			printKeyValue("Email", safe(actor.Email))
			printKeyValue("Name", safe(orDefault(actor.Name, "not set")))
			printKeyValue("Plan", safe(orDefault(actor.TierName, "none")))
			printKeyValue("Status", safe(subscriptionStatus(actor.SubscriptionStatus, actor.Subscription.TrialEndsAt, time.Now())))
			printKeyValue("Primary key", primaryKeyLabel(keys))
			fmt.Fprintln(os.Stderr)
			return nil
		},
	}
}

// registeredKeysStep is the step that fetches, with list, the keys
// registered for the account into keys. A failure fails the step: no keys
// fetched is not the same as no keys registered.
func registeredKeysStep(list func() ([]sdk.RemoteKey, error), keys *[]sdk.RemoteKey) step {
	return step{
		label: "Fetching your registered keys",
		done:  "Registered keys fetched",
		action: func() (string, error) {
			got, err := list()
			if err != nil {
				return "", fmt.Errorf("could not list your registered keys: %w", apiCause(err))
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
			return safe(k.Fingerprint)
		}
	}
	if len(keys) == 0 {
		return "none registered (create one with: secret identity generate --sync)"
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
