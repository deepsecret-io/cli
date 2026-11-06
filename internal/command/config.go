// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/spf13/cobra"

	"github.com/deepsecret-io/cli/internal/auth"
	"github.com/deepsecret-io/cli/internal/config"
	"github.com/deepsecret-io/cli/internal/console"
	"github.com/deepsecret-io/cli/internal/errs"
	"github.com/deepsecret-io/cli/internal/flags"
	"github.com/deepsecret-io/cli/internal/ui"
)

func newConfigCmd() *cobra.Command {
	var saveKey bool

	cmd := &cobra.Command{
		Use:     "config",
		Aliases: []string{"conf"},
		Short:   "Configure CLI settings (alias: conf)",
		Long: `Show the CLI's settings, or save an API key for later commands.

--save-api-key saves the key given with the global key options. Pass it on
stdin or in a file so it stays out of the process list and shell history.
A saved key is used when you are not logged in; a key given with a flag or
DS_API_KEY comes before the login.`,
		Example: `  secret config
  secret config --save-api-key --api-key-stdin < key.txt
  secret config --save-api-key --api-key-file ./key.txt`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if saveKey {
				if auth.FlagKey == "" {
					return fmt.Errorf("--save-api-key needs a key: give it with --api-key-stdin, --api-key-file, --api-key or DS_API_KEY")
				}
				// The file holds only the key, so one that cannot be read
				// is replaced whole.
				if err := config.Save(&config.Config{APIKey: auth.FlagKey}); err != nil {
					return fmt.Errorf("could not save the API key: %w", err)
				}
				ui.Success("API key saved to " + console.Safe(config.Path()) + ".")
				return nil
			}

			cfg, err := config.Load()
			switch {
			case errors.Is(err, fs.ErrNotExist):
				cfg = &config.Config{}
			case err != nil:
				return fmt.Errorf("could not read %s: %w", config.Path(), errs.PathCause(err))
			}
			saved := "not set"
			if cfg.APIKey != "" {
				saved = "set"
			}
			fmt.Fprintln(os.Stderr)
			ui.KeyValue("Config file", console.Safe(config.Path()))
			ui.KeyValue("API URL", config.APIBaseURL+" (compiled in)")
			ui.KeyValue("Saved API key", saved)
			fmt.Fprintln(os.Stderr)
			return nil
		},
	}

	cmd.Flags().BoolVar(&saveKey, "save-api-key", false, "Save the API key given with --api-key-stdin, --api-key-file, --api-key or DS_API_KEY")
	flags.SetGroup(cmd.Flags(), flags.GroupOptions, "save-api-key")

	return cmd
}
