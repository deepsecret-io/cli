// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/deepsecret-io/sdk"
	"github.com/deepsecret-io/sdk/api"
)

// Config stored at ~/.deepsecret/config.json
type Config struct {
	APIKey string `json:"api_key"`
}

func configDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		// Every caller needs the login, the keys or the settings, and
		// there is nowhere to keep them.
		detail := "The CLI keeps its login, keys and settings in ~/.deepsecret. Set HOME (USERPROFILE on Windows) and try again."
		if err != nil {
			detail = err.Error() + "\n\n" + detail
		}
		printDiagnostic(sevError, "Cannot find your home directory", detail)
		closeLog()
		os.Exit(1)
	}
	return filepath.Join(home, ".deepsecret")
}

func configPath() string {
	return filepath.Join(configDir(), "config.json")
}

func keysDir() string {
	return filepath.Join(configDir(), "keys")
}

// Sensitive fields (api_key, bearer token) are stored as plaintext in files
// with mode 0600 inside a 0700 directory. Operators who need stronger
// isolation should source the API key from a secrets manager (HashiCorp
// Vault, AWS Secrets Manager, 1Password CLI, etc.) and pass it via
// --api-key-file or --api-key-stdin.

func loadConfig() (*Config, error) {
	data, err := os.ReadFile(configPath())
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func saveConfig(c *Config) error {
	if err := os.MkdirAll(configDir(), 0700); err != nil {
		return err
	}
	// #nosec G117 -- the API key is what the config file holds; writePrivateFile keeps it 0600.
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("could not encode the config: %w", err)
	}
	return writePrivateFile(configPath(), data)
}

// writePrivateFile replaces path with data through a new 0600 file renamed
// over it, so the file is private even when an older one was not, a link
// at path is replaced rather than followed, and a reader never sees half
// of it.
func writePrivateFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	// After the rename this finds nothing; after a failure it removes the
	// temporary file.
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close() // the write error is returned and the file removed.
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// TokenFile stored at ~/.deepsecret/token.json
type TokenFile struct {
	Token     string `json:"token"`
	Email     string `json:"email"`
	ExpiresAt string `json:"expires_at"`
}

func tokenPath() string {
	return filepath.Join(configDir(), "token.json")
}

func saveToken(token, email, expiresAt string) error {
	if err := os.MkdirAll(configDir(), 0700); err != nil {
		return err
	}
	tf := TokenFile{Token: token, Email: email, ExpiresAt: expiresAt}
	data, err := json.MarshalIndent(tf, "", "  ")
	if err != nil {
		return fmt.Errorf("could not encode the login token: %w", err)
	}
	return writePrivateFile(tokenPath(), data)
}

// saveRefreshedToken stores a session token the SDK refreshed, keeping the
// email on record. The server revoked the previous token, so a token that
// cannot be saved leaves the next command without a session: the user is
// told, since the SDK carries on with the request that renewed it.
func saveRefreshedToken(token string, expiresAt time.Time) error {
	email := ""
	if tf, err := loadTokenFile(); err == nil {
		email = tf.Email
	}
	if err := saveToken(token, email, expiresAt.UTC().Format(time.RFC3339)); err != nil {
		printWarning("Could not save the renewed login session",
			fmt.Sprintf("%v\n\nThis command goes on, but the next one will fail until you sign in again with 'secret login'.", err))
		return err
	}
	api.Module(logger, "auth").Debug("session renewed", "expires_at", expiresAt)
	return nil
}

// errSessionExpired is a stored login session past its expiry.
var errSessionExpired = errors.New("the login session expired")

func loadToken() (string, error) {
	data, err := os.ReadFile(tokenPath())
	if err != nil {
		return "", err
	}
	var tf TokenFile
	if err := json.Unmarshal(data, &tf); err != nil {
		return "", err
	}
	if tf.Token == "" {
		return "", errors.New("the login token file holds no token")
	}
	token := tf.Token
	// Check expiry: if it does not parse, treat it as expired (fail closed)
	if tf.ExpiresAt != "" {
		exp, err := time.Parse(time.RFC3339, tf.ExpiresAt)
		if err != nil {
			return "", fmt.Errorf("the login token's expiry is not a time, so it counts as expired: %w", err)
		}
		if time.Now().After(exp) {
			return "", errSessionExpired
		}
	}
	return token, nil
}

func loadTokenFile() (*TokenFile, error) {
	data, err := os.ReadFile(tokenPath())
	if err != nil {
		return nil, err
	}
	var tf TokenFile
	if err := json.Unmarshal(data, &tf); err != nil {
		return nil, err
	}
	return &tf, nil
}

func removeToken() error {
	return os.Remove(tokenPath())
}

// resolveAuth picks the credential to use, in priority order: the API key
// given with a flag or DS_API_KEY, the login session, then the API key
// saved in the config file. It returns the credential and where it came
// from. The API URL is compiled in (see constants.go), so it returns no
// URL.
func resolveAuth() (key, source string, err error) {
	if apiKey != "" {
		return apiKey, keyOrigin, nil
	}
	token, tokenErr := loadToken()
	if tokenErr == nil {
		return "bearer:" + token, "login session", nil
	}
	if cfg, err := loadConfig(); err == nil && cfg.APIKey != "" {
		return cfg.APIKey, "saved API key", nil
	}
	summary := "not logged in"
	if errors.Is(tokenErr, errSessionExpired) {
		summary = "your login session expired"
	}
	return "", "", withDetail(errors.New(summary),
		"Sign in with 'secret login', or save an API key for later commands:\n  secret config --save-api-key --api-key-stdin")
}

// newAuthenticatedClient creates an SDK client pointed at the compiled-in API
// URL using whichever credential source resolveAuth picks.
func newAuthenticatedClient() (*Client, error) {
	key, source, err := resolveAuth()
	if err != nil {
		return nil, err
	}
	api.Module(logger, "auth").Debug("credentials resolved", "source", source, "api_url", apiBaseURL)
	if token, ok := strings.CutPrefix(key, "bearer:"); ok && apiKey == "" {
		return newSessionClient(token)
	}
	return NewClient(apiBaseURL, key)
}

// newSessionClient creates a client for a login session's token. The
// session renews its token while in use, and each renewal revokes the
// token it replaces, so every new token is saved for the next command.
func newSessionClient(token string) (*Client, error) {
	c, err := NewClient(apiBaseURL, "bearer:"+token)
	if err != nil {
		return nil, err
	}
	c.SetSessionStore(sdk.SessionStore{Load: loadToken, Save: saveRefreshedToken})
	return c, nil
}

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
		RunE: func(cmd *cobra.Command, args []string) error {
			if saveKey {
				if apiKey == "" {
					return fmt.Errorf("--save-api-key needs a key: give it with --api-key-stdin, --api-key-file, --api-key or DS_API_KEY")
				}
				// The file holds only the key, so one that cannot be read
				// is replaced whole.
				if err := saveConfig(&Config{APIKey: apiKey}); err != nil {
					return fmt.Errorf("could not save the API key: %w", err)
				}
				printSuccess("API key saved to " + safe(configPath()) + ".")
				return nil
			}

			cfg, err := loadConfig()
			switch {
			case errors.Is(err, fs.ErrNotExist):
				cfg = &Config{}
			case err != nil:
				return fmt.Errorf("could not read %s: %w", configPath(), pathCause(err))
			}
			saved := "not set"
			if cfg.APIKey != "" {
				saved = "set"
			}
			fmt.Fprintln(os.Stderr)
			printKeyValue("Config file", safe(configPath()))
			printKeyValue("API URL", apiBaseURL+" (compiled in)")
			printKeyValue("Saved API key", saved)
			fmt.Fprintln(os.Stderr)
			return nil
		},
	}

	cmd.Flags().BoolVar(&saveKey, "save-api-key", false, "Save the API key given with --api-key-stdin, --api-key-file, --api-key or DS_API_KEY")
	setGroup(cmd.Flags(), groupOptions, "save-api-key")

	return cmd
}

// readPassword reads a password from the controlling terminal without
// echoing. It prefers /dev/tty over stdin so the prompt still works when the
// caller is piping data into stdin (e.g. `kubectl ... | secret encrypt`),
// where stdin is a pipe and term.ReadPassword would fail with "inappropriate
// ioctl for device". The underlying byte buffer is overwritten with zeros
// before returning; the only remaining copy is the immutable Go string the
// caller holds.
func readPassword(prompt string) (string, error) {
	if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		defer tty.Close()
		fmt.Fprint(tty, prompt)
		pw, err := term.ReadPassword(int(tty.Fd()))
		fmt.Fprintln(tty)
		if err != nil {
			zeroBytes(pw)
			return "", fmt.Errorf("could not read the password: %w", err)
		}
		defer zeroBytes(pw)
		return strings.TrimSpace(string(pw)), nil
	}

	// Fallback: stdin is the only thing left. This is the path on systems
	// without /dev/tty (e.g. Windows without ConPTY, some CI containers).
	fmt.Fprint(os.Stderr, prompt)
	pw, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		zeroBytes(pw)
		return "", fmt.Errorf("could not read the password: %w", err)
	}
	defer zeroBytes(pw)
	return strings.TrimSpace(string(pw)), nil
}

// zeroBytes overwrites b with zeros. Best-effort: a future Go version could
// theoretically optimise this away, but the compiler currently does not when
// the slice escapes (which it does, via pw being a function argument).
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// readPasswordConfirm reads and confirms a new password.
func readPasswordConfirm(prompt string) (string, error) {
	pw, err := readPassword(prompt)
	if err != nil {
		return "", err
	}
	if pw == "" {
		return "", nil
	}
	confirm, err := readPassword("Confirm password: ")
	if err != nil {
		return "", err
	}
	if pw != confirm {
		return "", fmt.Errorf("passwords do not match")
	}
	return pw, nil
}
