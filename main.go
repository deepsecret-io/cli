// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

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

	"github.com/spf13/cobra"

	"github.com/deepsecret-io/sdk/api"
)

var (
	// version is a release's vMAJOR.MINOR.PATCH, set by `task release`;
	// every other build is "dev".
	version = "dev"
	apiKey  string
	// keyOrigin names where apiKey came from: a flag, or DS_API_KEY.
	keyOrigin   string
	apiKeyFile  string
	apiKeyStdin bool
	debug       bool
	// showProgress draws a transfer's progress (--progress). Without it the
	// output stays plain for pipes, scripts and logs.
	showProgress bool
)

// rootCtx is cancelled on SIGINT/SIGTERM so long-running operations
// (uploads/downloads) can shut down gracefully instead of being SIGKILL'd.
var rootCtx context.Context

func main() {
	// os.Interrupt is Ctrl+C on every OS; SIGTERM is what service managers
	// send on Unix, and Go maps console close and shutdown to it on
	// Windows.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	rootCtx = ctx

	root := newRootCmd()

	start := time.Now()
	err := root.ExecuteContext(rootCtx)
	elapsed := logDuration(time.Since(start))
	if err == nil {
		logger.Info("command finished", "elapsed", elapsed)
		closeLog()
		return
	}
	logger.Error("command failed", "error", err, "elapsed", elapsed)
	closeLog()
	os.Exit(reportError(err))
}

// reportError prints err as an Error block and returns the exit code.
func reportError(err error) int {
	switch {
	case rootCtx != nil && rootCtx.Err() != nil:
		// Ctrl+C or SIGTERM: requests in flight unwind with
		// context.Canceled. Say so in one block rather than the error
		// chain, keeping what the error says to do next (how to finish an
		// interrupted transfer), and exit 130, the code of a command
		// stopped by SIGINT. A timeout is not an interrupt: it is reported
		// as the error it is.
		printDiagnostic(sevError, "Interrupted", joinDetail("The command stopped before it finished.", err))
		return 130
	case api.IsMaintenanceError(err):
		printDiagnostic(sevError, "The DeepSecret API is under maintenance", api.MaintenanceMessage(err)+"\n\nTry again shortly.")
		return 1
	case credentialSource != "" && errors.Is(err, api.ErrUnauthorized):
		// The server refused the credential itself, whatever the command
		// asked for: name it, and keep what the error says to do next.
		summary, detail := refusedCredential(credentialSource)
		printDiagnostic(sevError, summary, joinDetail(detail, err))
		return 1
	}
	// 402: paying would let the request in (a plan that ended, or a
	// feature it lacks), and the server's message says what to do, so it
	// is the whole summary, whatever the command was doing.
	var ae *api.APIError
	if errors.As(err, &ae) && ae.StatusCode == http.StatusPaymentRequired && ae.Message != "" {
		printDiagnostic(sevError, ae.Message, joinDetail("", err))
		return 1
	}
	summary, detail := describeError(err)
	printDiagnostic(sevError, summary, detail)
	return 1
}

// closeLog closes the log file DS_LOG_PATH names, once the command is
// done.
var closeLog = func() {}

// versionString is what --version prints: the version, then the commit it
// was built from and the SDK version it uses, as the build recorded them.
func versionString() string {
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
	for _, d := range info.Deps {
		if d.Path == "github.com/deepsecret-io/sdk" {
			sdk := "sdk " + d.Version
			if d.Replace != nil {
				sdk += " from " + d.Replace.Path
			}
			notes = append(notes, sdk)
		}
	}
	if len(notes) == 0 {
		return version
	}
	return version + " (" + strings.Join(notes, ", ") + ")"
}

// newRootCmd builds the command tree: every command, its flags and help.
func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "secret",
		Short:         "DeepSecret CLI: E2E encrypted secrets manager",
		Version:       versionString(),
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
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
				apiKey = resolved
				keyOrigin = "--api-key-file"
				if apiKeyStdin {
					keyOrigin = "--api-key-stdin"
				}
			case apiKey != "":
				keyOrigin = "--api-key"
			default:
				apiKey = os.Getenv("DS_API_KEY")
				keyOrigin = "DS_API_KEY"
			}
			closeLogFile, err := setupLogging(debug)
			if err != nil {
				return err
			}
			closeLog = closeLogFile
			logger.Info("command started", "command", cmd.CommandPath(), "version", version, "go", runtime.Version(), "platform", runtime.GOOS+"/"+runtime.GOARCH)
			return nil
		},
	}

	pf := root.PersistentFlags()
	pf.StringVar(&apiKeyFile, "api-key-file", "", "Read the API key from `file` (preferred over --api-key)")
	pf.BoolVar(&apiKeyStdin, "api-key-stdin", false, "Read the API key from stdin (preferred over --api-key)")
	pf.StringVar(&apiKey, "api-key", "", "API `key` (visible in process listings; prefer --api-key-file or DS_API_KEY)")
	pf.BoolVar(&debug, "debug", false, "Write debug logs to stderr, with each transfer's plan (DS_LOG sets the level, or json; DS_LOG_PATH a file instead)")
	pf.BoolVar(&showProgress, "progress", false, "Show a transfer's progress: each connection, redrawn live, on a terminal; a line every 5s when redirected")
	setGroup(pf, groupGlobal, "api-key-file", "api-key-stdin", "api-key", "debug", "progress")
	root.MarkFlagsMutuallyExclusive("api-key", "api-key-file", "api-key-stdin")
	root.SetUsageFunc(usage)

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
			return "", fmt.Errorf("could not read --api-key-file %s: %w", apiKeyFile, pathCause(err))
		}
		// Opened to read only: once the key is read, a close error loses
		// nothing.
		defer func() { _ = f.Close() }()
		// A key is short; read a bounded amount, so a device or a huge
		// file cannot exhaust memory.
		b, err := io.ReadAll(io.LimitReader(f, maxAPIKeyLen+1))
		if err != nil {
			return "", fmt.Errorf("could not read --api-key-file %s: %w", apiKeyFile, pathCause(err))
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
