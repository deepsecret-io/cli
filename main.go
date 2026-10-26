// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/deepsecret-io/sdk/api"
)

var (
	version     = "0.1.0"
	apiKey      string
	apiKeyFile  string
	apiKeyStdin bool
	debug       bool
)

// rootCtx is cancelled on SIGINT/SIGTERM so long-running operations
// (uploads/downloads) can shut down gracefully instead of being SIGKILL'd.
var rootCtx context.Context

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	rootCtx = ctx

	root := &cobra.Command{
		Use:           "secret",
		Short:         "DeepSecret CLI: E2E encrypted secrets manager",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			resolved, err := resolveAPIKey()
			if err != nil {
				return err
			}
			if resolved != "" {
				apiKey = resolved
			} else if apiKey == "" {
				apiKey = os.Getenv("DS_API_KEY")
			}
			if !debug && os.Getenv("DS_DEBUG") == "1" {
				debug = true
			}
			return nil
		},
	}

	root.PersistentFlags().StringVar(&apiKeyFile, "api-key-file", "", "Read API key from file (preferred over --api-key)")
	root.PersistentFlags().BoolVar(&apiKeyStdin, "api-key-stdin", false, "Read API key from stdin (preferred over --api-key)")
	root.PersistentFlags().StringVar(&apiKey, "api-key", "", "API key (visible in process listings; prefer --api-key-file or DS_API_KEY)")
	root.PersistentFlags().BoolVar(&debug, "debug", false, "Show verbose debug logs for every step (or DS_DEBUG=1)")

	root.AddCommand(
		newLoginCmd(),
		newLogoutCmd(),
		newDoctorCmd(),
		newEncryptCmd(),
		newDecryptCmd(),
		newResumeCmd(),
		newListCmd(),
		newDescribeCmd(),
		newDeleteCmd(),
		newRevokeCmd(),
		newPolicyCmd(),
		newConfigCmd(),
		newIdentityCmd(),
		newGroupsCmd(),
		newWhoamiCmd(),
	)

	if err := root.ExecuteContext(rootCtx); err != nil {
		// Ctrl+C / SIGTERM: rootCtx fires, in-flight requests unblock with
		// context.Canceled wrapped through the call stack. Render a
		// single-line "cancelled" notice and exit 130 (UNIX convention for
		// terminated by SIGINT) instead of dumping a noisy error chain.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(rootCtx.Err(), context.Canceled) {
			fmt.Fprintf(os.Stderr, "\n  %s✗%s cancelled by user\n", ansiYellow, ansiReset)
			os.Exit(130)
		}
		if api.IsMaintenanceError(err) {
			printError("The DeepSecret API is currently under maintenance.\n  " + api.MaintenanceMessage(err) + "\n  Please try again shortly.")
			os.Exit(1)
		}
		if _, ok := err.(*displayedError); !ok {
			printError(err.Error())
		}
		os.Exit(1)
	}
}

// resolveAPIKey returns the API key from --api-key-file or --api-key-stdin if
// either is set, in that priority. Both options keep the secret out of argv,
// which is visible to other local users via `ps`. Returns "" when neither flag
// is provided so the caller can fall back to --api-key / DS_API_KEY.
func resolveAPIKey() (string, error) {
	if apiKeyFile != "" {
		b, err := os.ReadFile(apiKeyFile)
		if err != nil {
			return "", fmt.Errorf("read --api-key-file: %w", err)
		}
		key := strings.TrimSpace(string(b))
		if key == "" {
			return "", fmt.Errorf("--api-key-file is empty")
		}
		return key, nil
	}
	if apiKeyStdin {
		r := bufio.NewReader(os.Stdin)
		line, err := r.ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("read --api-key-stdin: %w", err)
		}
		key := strings.TrimSpace(line)
		if key == "" {
			return "", fmt.Errorf("--api-key-stdin received empty input")
		}
		return key, nil
	}
	return "", nil
}
