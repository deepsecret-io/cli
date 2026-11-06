// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/deepsecret-io/cli/internal/auth"
	"github.com/deepsecret-io/cli/internal/config"
	"github.com/deepsecret-io/cli/internal/console"
	"github.com/deepsecret-io/cli/internal/errs"
	"github.com/deepsecret-io/cli/internal/flags"
	"github.com/deepsecret-io/cli/internal/logging"
	"github.com/deepsecret-io/cli/internal/login"
	"github.com/deepsecret-io/cli/internal/ui"
)

func newLoginCmd() *cobra.Command {
	var check bool

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate via browser SSO",
		Long: `Open the browser to authenticate with Google SSO. A short-lived token
is stored locally for CLI usage. It renews while you use the CLI, for up
to 7 days from sign-in; after an hour unused, sign in again. API keys are
still supported for CI/CD.

Examples:
  secret login          # authenticate via browser
  secret login --check  # show current auth status`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if check {
				return showAuthStatus()
			}
			return login.Browser(cmd.Context())
		},
	}

	cmd.Flags().BoolVar(&check, "check", false, "Show the current authentication status instead of signing in")
	flags.SetGroup(cmd.Flags(), flags.GroupOptions, "check")
	return cmd
}

func newLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Revoke and remove the stored login token",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			tf, err := config.LoadTokenFile()
			if err != nil || tf.Token == "" {
				return errors.New("not logged in: there is no login session on this device")
			}
			// Revoke server-side first so a copy of the token stops
			// working, then remove it locally whatever the outcome.
			revokeErr := login.Revoke(cmd.Context(), config.APIBaseURL, tf.Token)
			if err := config.RemoveToken(); err != nil {
				return fmt.Errorf("could not remove the login token: %w", err)
			}
			if revokeErr != nil {
				ui.Warning("The server could not revoke the login token",
					fmt.Sprintf("%v\n\nIt was removed from this device, but a copy of it stays valid until it expires, within an hour.", errs.APICause(revokeErr)))
				ui.Success("Logged out on this device.")
				return nil
			}
			logging.Module(logging.Log, "auth").Info("logged out", "email", tf.Email)
			ui.Success("Logged out: the session is revoked, and its token removed.")
			return nil
		},
	}
}

// showAuthStatus prints the login session, the saved API key, and which
// credential commands use: an API key given with a flag or DS_API_KEY,
// else the login session, else the saved key (auth.Resolve).
func showAuthStatus() error {
	fmt.Fprintln(os.Stderr)
	if tf, err := config.LoadTokenFile(); err == nil && tf.Token != "" {
		ui.KeyValue("Login", console.Safe(orDefault(tf.Email, "account not recorded"))+" (browser sign-in)")
		ui.KeyValue("Token expires", tokenExpiry(tf.ExpiresAt, time.Now()))
	} else {
		ui.KeyValue("Login", "not logged in (run: secret login)")
	}
	if cfg, err := config.Load(); err == nil && cfg.APIKey != "" {
		ui.KeyValue("Saved API key", "set (used when not logged in)")
	}
	_, source, err := auth.Resolve()
	if err != nil {
		source = "none"
	}
	ui.KeyValue("In use", source)
	ui.KeyValue("API URL", config.APIBaseURL)
	fmt.Fprintln(os.Stderr)
	return nil
}

// tokenExpiry says when the stored session token, expiring at expiresAt,
// expires: it renews while in use, so this is when an unused session ends.
func tokenExpiry(expiresAt string, now time.Time) string {
	if expiresAt == "" {
		return "not recorded"
	}
	exp, err := time.Parse(time.RFC3339, expiresAt)
	switch {
	case err != nil:
		return "not readable, so it counts as expired (run: secret login)"
	case !now.Before(exp):
		return "expired (run: secret login)"
	}
	return fmt.Sprintf("%s, in %s unless it renews while in use", exp.Local().Format("15:04:05"), ui.FormatRemaining(exp.Sub(now)))
}
