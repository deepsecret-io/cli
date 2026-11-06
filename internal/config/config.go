// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package config reads and writes what the CLI keeps in ~/.deepsecret: its
// paths, the config file and the login token.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/deepsecret-io/cli/internal/errs"
)

// Config stored at ~/.deepsecret/config.json
type Config struct {
	APIKey string `json:"api_key"`
}

// CheckHome refuses to go on without a home directory: there is nowhere to
// keep the login, the keys or the settings. The root command checks it before
// a command runs, so Dir has one.
func CheckHome() error {
	_, err := home()
	if err == nil {
		return nil
	}
	return errs.WithDetail(errors.New("cannot find your home directory"),
		err.Error()+"\n\nThe CLI keeps its login, keys and settings in ~/.deepsecret. Set HOME (USERPROFILE on Windows) and try again.")
}

// home is the user's home directory. A relative one is refused: it would put
// key files wherever the command runs.
func home() (string, error) {
	dir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("the home directory %q is not an absolute path", dir)
	}
	return dir, nil
}

// Dir is the folder the CLI keeps everything in, ~/.deepsecret. Without a
// home directory, which CheckHome rules out first, it panics: a path relative
// to the current folder would put key files wherever the command runs.
func Dir() string {
	dir, err := home()
	if err != nil {
		panic("config: no home directory: CheckHome must pass before Dir is used")
	}
	return filepath.Join(dir, ".deepsecret")
}

// Path is the config file's path.
func Path() string {
	return filepath.Join(Dir(), "config.json")
}

// KeysDir is the folder of this device's key pairs.
func KeysDir() string {
	return filepath.Join(Dir(), "keys")
}

// Sensitive fields (api_key, bearer token) are stored as plaintext in files
// with mode 0600 inside a 0700 directory. Operators who need stronger
// isolation should source the API key from a secrets manager (HashiCorp
// Vault, AWS Secrets Manager, 1Password CLI, etc.) and pass it via
// --api-key-file or --api-key-stdin.

// Load reads the config file.
func Load() (*Config, error) {
	data, err := os.ReadFile(Path())
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// Save writes the config file, private to the user.
func Save(c *Config) error {
	if err := os.MkdirAll(Dir(), 0700); err != nil {
		return err
	}
	// #nosec G117 -- the API key is what the config file holds; writePrivateFile keeps it 0600.
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("could not encode the config: %w", err)
	}
	return writePrivateFile(Path(), data)
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
