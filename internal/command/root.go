// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package command holds the secret CLI's cobra commands, one file per command
// tree, and the flow each runs. The other internal packages hold what they
// share.
package command

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	rtdebug "runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/deepsecret-io/deepsecret-go/apierror"
	"github.com/deepsecret-io/deepsecret-go/secrets"
	"github.com/spf13/cobra"

	"github.com/deepsecret-io/cli/internal/auth"
	"github.com/deepsecret-io/cli/internal/config"
	"github.com/deepsecret-io/cli/internal/errs"
	"github.com/deepsecret-io/cli/internal/flags"
	"github.com/deepsecret-io/cli/internal/identity"
	"github.com/deepsecret-io/cli/internal/logging"
	"github.com/deepsecret-io/cli/internal/ui"
)

var (
	apiKeyFile  string
	apiKeyStdin bool
	debug       bool
)

// Execute runs the command the arguments name, and returns the exit code.
func Execute(version string) int {
	// os.Interrupt is Ctrl+C on every OS; SIGTERM is what service managers
	// send on Unix, and Go maps console close and shutdown to it on
	// Windows.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	root := newRootCmd(version)

	start := time.Now()
	err := root.ExecuteContext(ctx)
	elapsed := logging.Duration(time.Since(start))
	if err == nil {
		logging.Log.Info("command finished", "elapsed", elapsed)
		logging.Close()
		return 0
	}
	logging.Log.Error("command failed", "error", err, "elapsed", elapsed)
	logging.Close()
	return reportError(ctx, err)
}

// reportError prints err as an Error block and returns the exit code.
func reportError(ctx context.Context, err error) int {
	switch {
	case ctx.Err() != nil:
		// Ctrl+C or SIGTERM: requests in flight unwind with
		// context.Canceled. Say so in one block rather than the error
		// chain, keeping what the error says to do next (how to finish an
		// interrupted transfer), and exit 130, the code of a command
		// stopped by SIGINT. A timeout is not an interrupt: it is reported
		// as the error it is.
		ui.Diagnostic(ui.SevError, "Interrupted", errs.JoinDetail("The command stopped before it finished.", err))
		return 130
	case apierror.IsMaintenanceError(err):
		ui.Diagnostic(ui.SevError, "The DeepSecret API is under maintenance", apierror.MaintenanceMessage(err)+"\n\nTry again shortly.")
		return 1
	case auth.Source != "" && errors.Is(err, apierror.ErrUnauthorized):
		// The server refused the credential itself, whatever the command
		// asked for: name it, and keep what the error says to do next.
		summary, detail := auth.Refused(auth.Source)
		ui.Diagnostic(ui.SevError, summary, errs.JoinDetail(detail, err))
		return 1
	}
	// 402: paying would let the request in (a plan that ended, or a
	// feature it lacks), and the server's message says what to do, so it
	// is the whole summary, whatever the command was doing.
	var ae *apierror.Error
	if errors.As(err, &ae) && ae.StatusCode == http.StatusPaymentRequired && ae.Message != "" {
		ui.Diagnostic(ui.SevError, ae.Message, errs.JoinDetail("", err))
		return 1
	}
	// A secret sealed before its name was signed cannot be opened by this
	// version: say so, and what to do, instead of the manifest check that
	// refused it.
	if errors.Is(err, secrets.ErrOutdatedManifest) {
		ui.Diagnostic(ui.SevError, "This secret was made by an earlier version of DeepSecret", "This version cannot open it. Ask the sender to send it again.")
		return 1
	}
	summary, detail := describeFailure(ctx, err)
	ui.Diagnostic(ui.SevError, summary, detail)
	return 1
}

// versionString is what --version prints: the version, then the commit it
// was built from and the SDK version it uses, as the build recorded them.
func versionString(version string) string {
	info, ok := rtdebug.ReadBuildInfo()
	if !ok {
		return version
	}
	var notes []string
	for _, s := range info.Settings {
		switch {
		case s.Key == "vcs.revision" && len(s.Value) >= 7:
			notes = append(notes, "commit "+s.Value[:7])
		case s.Key == "vcs.modified" && s.Value == "true":
			notes = append(notes, "uncommitted changes")
		}
	}
	if note := sdkNote(info.Deps); note != "" {
		notes = append(notes, note)
	}
	if len(notes) == 0 {
		return version
	}
	return version + " (" + strings.Join(notes, ", ") + ")"
}

// sdkModule is the SDK's module path, which --version looks for in the build.
const sdkModule = "github.com/deepsecret-io/deepsecret-go"

// sdkNote says which SDK version the build uses, and where it came from when a
// go.work replaced it; "" when it is not among deps.
func sdkNote(deps []*rtdebug.Module) string {
	for _, d := range deps {
		if d.Path == sdkModule {
			note := "sdk " + d.Version
			if d.Replace != nil {
				note += " from " + d.Replace.Path
			}
			return note
		}
	}
	return ""
}

// newRootCmd builds the command tree: every command, its flags and help.
func newRootCmd(version string) *cobra.Command {
	identity.AppVersion = version
	root := &cobra.Command{
		Use:           "secret",
		Short:         "DeepSecret CLI: E2E encrypted secrets manager",
		Version:       versionString(version),
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			// cobra checks flag groups after this hook; check them first,
			// so conflicting key flags fail before a key is read.
			if err := cmd.ValidateFlagGroups(); err != nil {
				return err
			}
			resolved, err := resolveAPIKey()
			if err != nil {
				return err
			}
			switch {
			case resolved != "":
				auth.FlagKey = resolved
				auth.FlagKeyOrigin = "--api-key-file"
				if apiKeyStdin {
					auth.FlagKeyOrigin = "--api-key-stdin"
				}
			case auth.FlagKey != "":
				auth.FlagKeyOrigin = "--api-key"
			default:
				auth.FlagKey = os.Getenv("DS_API_KEY")
				auth.FlagKeyOrigin = "DS_API_KEY"
			}
			if err := logging.Setup(debug); err != nil {
				return err
			}
			if usesHome(cmd) {
				if err := config.CheckHome(); err != nil {
					return err
				}
			}
			logging.Log.Info("command started", "command", cmd.CommandPath(), "version", version, "go", runtime.Version(), "platform", runtime.GOOS+"/"+runtime.GOARCH)
			return nil
		},
	}

	pf := root.PersistentFlags()
	pf.StringVar(&apiKeyFile, "api-key-file", "", "Read the API key from `file` (preferred over --api-key)")
	pf.BoolVar(&apiKeyStdin, "api-key-stdin", false, "Read the API key from stdin (preferred over --api-key)")
	pf.StringVar(&auth.FlagKey, "api-key", "", "API `key` (visible in process listings; prefer --api-key-file or DS_API_KEY)")
	pf.BoolVar(&debug, "debug", false, "Write debug logs to stderr, with each transfer's plan (DS_LOG sets the level, or json; DS_LOG_PATH a file instead)")
	pf.BoolVar(&ui.ShowProgress, "progress", false, "Show a transfer's progress: each connection, redrawn live, on a terminal; a line every 5s when redirected")
	pf.StringVar(&identity.AWSProfile, "aws-profile", "", "AWS `profile` for key pairs protected by AWS KMS (default: AWS_PROFILE and the AWS default credential chain)")
	flags.SetGroup(pf, flags.GroupGlobal, "api-key-file", "api-key-stdin", "api-key", "debug", "progress", "aws-profile")
	root.MarkFlagsMutuallyExclusive("api-key", "api-key-file", "api-key-stdin")
	root.SetUsageFunc(flags.Usage)

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
	return root
}

// usesHome reports whether cmd keeps anything in ~/.deepsecret: every command
// but cobra's own for help and shell completion, which work without a home
// directory.
func usesHome(cmd *cobra.Command) bool {
	for c := cmd; c != nil; c = c.Parent() {
		switch c.Name() {
		case "help", "completion", cobra.ShellCompRequestCmd, cobra.ShellCompNoDescRequestCmd:
			return false
		}
	}
	return true
}

// maxAPIKeyLen bounds an API key read from a file or stdin.
const maxAPIKeyLen = 4096

// resolveAPIKey returns the API key from --api-key-file or --api-key-stdin if
// either is set, in that priority. Both options keep the secret out of argv,
// which is visible to other local users via `ps`. Returns "" when neither flag
// is provided so the caller can fall back to --api-key / DS_API_KEY.
func resolveAPIKey() (string, error) {
	if apiKeyFile != "" {
		f, err := os.Open(apiKeyFile) // #nosec G304 -- the user's own --api-key-file; the CLI runs with their permissions.
		if err != nil {
			return "", fmt.Errorf("could not read --api-key-file %s: %w", apiKeyFile, errs.PathCause(err))
		}
		// Opened to read only: once the key is read, a close error loses
		// nothing.
		defer func() { _ = f.Close() }()
		// A key is short; read a bounded amount, so a device or a huge
		// file cannot exhaust memory.
		b, err := io.ReadAll(io.LimitReader(f, maxAPIKeyLen+1))
		if err != nil {
			return "", fmt.Errorf("could not read --api-key-file %s: %w", apiKeyFile, errs.PathCause(err))
		}
		if len(b) > maxAPIKeyLen {
			return "", fmt.Errorf("--api-key-file is over %d bytes; it should hold only the key", maxAPIKeyLen)
		}
		key := strings.TrimSpace(string(b))
		if key == "" {
			return "", fmt.Errorf("--api-key-file is empty")
		}
		return key, nil
	}
	if apiKeyStdin {
		r := bufio.NewReader(io.LimitReader(os.Stdin, maxAPIKeyLen+1))
		line, err := r.ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("could not read the API key from stdin: %w", err)
		}
		if len(line) > maxAPIKeyLen {
			return "", fmt.Errorf("--api-key-stdin read over %d bytes without a line end; send only the key", maxAPIKeyLen)
		}
		key := strings.TrimSpace(line)
		if key == "" {
			return "", fmt.Errorf("--api-key-stdin read an empty key")
		}
		return key, nil
	}
	return "", nil
}
