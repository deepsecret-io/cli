// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/deepsecret-io/sdk"
)

func newWhoamiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Show the authenticated actor",
		RunE: func(cmd *cobra.Command, args []string) error {
			dbg("whoami", "fetching account info")
			c, err := newAuthenticatedClient()
			if err != nil {
				return err
			}

			var actor sdk.ActorInfo
			var primaryFP string

			steps := []step{
				{
					label: "Fetching actor info",
					action: func() (string, error) {
						info, err := c.WhoAmI()
						if err != nil {
							return "", err
						}
						actor = *info
						return fmt.Sprintf("email=%s", actor.Email), nil
					},
				},
				{
					label: "Fetching primary identity",
					action: func() (string, error) {
						keys, err := c.ListRemoteKeys()
						if err != nil {
							return "no keys registered", nil
						}
						for _, k := range keys {
							if k.IsPrimary {
								primaryFP = k.Fingerprint
								return fmt.Sprintf("fingerprint=%s", k.Fingerprint[:16]), nil
							}
						}
						return "no primary key", nil
					},
				},
			}

			if err := runPipeline("Whoami", steps, nil); err != nil {
				return err
			}

			fmt.Fprintln(os.Stderr)
			kv := func(k, v string) { fmt.Fprintf(os.Stderr, "  %s%-14s%s %s\n", ansiDim, k, ansiReset, v) }
			kv("ID", actor.ID)
			kv("Email", actor.Email)
			name := actor.Name
			if name == "" {
				name = actor.Email
			}
			kv("Name", name)
			tier := actor.TierName
			if tier == "" {
				tier = "None"
			}
			kv("Plan", tier)
			kv("Status", subscriptionStatus(actor.SubscriptionStatus, actor.Subscription.TrialEndsAt, time.Now()))
			if primaryFP != "" {
				kv("Identity", primaryFP)
			}
			fmt.Fprintln(os.Stderr)

			return nil
		},
	}
}

// subscriptionStatus describes the subscription status for whoami. Without
// a subscription it shows the free trial and when it ends, or when it
// ended: the API reports "inactive" during a trial, which gives access.
func subscriptionStatus(status string, trialEndsAt *string, now time.Time) string {
	if status == "active" || trialEndsAt == nil {
		return status
	}
	ends, err := time.Parse(time.RFC3339, *trialEndsAt)
	if err != nil {
		return status
	}
	if now.Before(ends) {
		return "Free trial, ends " + ends.Local().Format("2 Jan 2006 15:04")
	}
	return status + ", free trial ended " + ends.Local().Format("2 Jan 2006")
}
