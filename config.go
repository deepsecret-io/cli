// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/deepsecret-io/sdk"
)

// Config stored at ~/.deepsecret/config.json
type Config struct {
	APIKey string `json:"api_key"`
}

func configDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		fmt.Fprintf(os.Stderr, "  %s✗%s cannot determine home directory: %v\n", ansiRed, ansiReset, err)
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
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	return os.WriteFile(configPath(), data, 0600)
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
		return fmt.Errorf("failed to marshal token: %w", err)
	}
	// Write a temporary file (0600) and rename it over the token, so another
	// run reading the token never sees half of one.
	tmp, err := os.CreateTemp(configDir(), "token-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), tokenPath())
}

// saveRefreshedToken stores a session token the SDK refreshed, keeping the
// email on record. The server revoked the previous token.
func saveRefreshedToken(token string, expiresAt time.Time) error {
	email := ""
	if tf, err := loadTokenFile(); err == nil {
		email = tf.Email
	}
	if err := saveToken(token, email, expiresAt.UTC().Format(time.RFC3339)); err != nil {
		dbgErr("auth", fmt.Errorf("save refreshed session: %w", err))
		return err
	}
	dbg("auth", "session refreshed, expires %s", expiresAt.Local().Format("15:04:05"))
	return nil
}

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
		return "", fmt.Errorf("empty token")
	}
	token := tf.Token
	// Check expiry — if parse fails, treat as expired (fail closed)
	if tf.ExpiresAt != "" {
		exp, err := time.Parse(time.RFC3339, tf.ExpiresAt)
		if err != nil {
			return "", fmt.Errorf("token expiry parse failed, treating as expired: %w", err)
		}
		if time.Now().After(exp) {
			return "", fmt.Errorf("token expired")
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

// resolveAuth picks the authentication credential to use, in priority order:
// --api-key flag / DS_API_KEY env > login token > config-file api_key.
// The API URL is hardcoded at compile time (see constants.go), so this
// function deliberately returns no URL.
func resolveAuth() (string, error) {
	if apiKey != "" {
		return apiKey, nil
	}
	if token, err := loadToken(); err == nil {
		return "bearer:" + token, nil
	}
	if cfg, err := loadConfig(); err == nil && cfg.APIKey != "" {
		return cfg.APIKey, nil
	}
	return "", fmt.Errorf("not authenticated. Run: secret login\n  Or set an API key: secret config --api-key <key>")
}

// newAuthenticatedClient creates an SDK client pointed at the compiled-in API
// URL using whichever credential source resolveAuth picks.
func newAuthenticatedClient() (*Client, error) {
	key, err := resolveAuth()
	if err != nil {
		dbgErr("auth", err)
		return nil, err
	}
	dbg("auth", "api_url=%s key_set=true", apiBaseURL)
	c, err := NewClient(apiBaseURL, key)
	if err != nil {
		return nil, err
	}
	// A login session (not an API key) is refreshed before its one-hour
	// token expires; each new token is saved for the next command.
	if apiKey == "" && strings.HasPrefix(key, "bearer:") {
		c.SetSessionStore(sdk.SessionStore{Load: loadToken, Save: saveRefreshedToken})
	}
	return c, nil
}

func newConfigCmd() *cobra.Command {
	var setKey string

	cmd := &cobra.Command{
		Use:     "config",
		Aliases: []string{"conf"},
		Short:   "Configure CLI settings (alias: conf)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _ := loadConfig()
			if cfg == nil {
				cfg = &Config{}
			}

			if setKey != "" {
				cfg.APIKey = setKey
				if err := saveConfig(cfg); err != nil {
					return fmt.Errorf("failed to save config: %w", err)
				}
				fmt.Println("Configuration saved.")
				return nil
			}

			fmt.Printf("Config file: %s\n", configPath())
			fmt.Printf("API URL:     %s (compiled in)\n", apiBaseURL)
			if cfg.APIKey != "" {
				fmt.Println("API Key:     (set)")
			} else {
				fmt.Println("API Key:     (not set)")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&setKey, "api-key", "", "Set API key")

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
			return "", fmt.Errorf("read password: %w", err)
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
		return "", fmt.Errorf("read password: %w", err)
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
