// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/deepsecret-io/cli/internal/logging"
	"github.com/deepsecret-io/cli/internal/ui"
)

// TokenFile stored at ~/.deepsecret/token.json
type TokenFile struct {
	Token     string `json:"token"`
	Email     string `json:"email"`
	ExpiresAt string `json:"expires_at"`
}

func tokenPath() string {
	return filepath.Join(Dir(), "token.json")
}

// SaveToken writes the login token, private to the user.
func SaveToken(token, email, expiresAt string) error {
	if err := os.MkdirAll(Dir(), 0700); err != nil {
		return err
	}
	tf := TokenFile{Token: token, Email: email, ExpiresAt: expiresAt}
	data, err := json.MarshalIndent(tf, "", "  ")
	if err != nil {
		return fmt.Errorf("could not encode the login token: %w", err)
	}
	return writePrivateFile(tokenPath(), data)
}

// SaveRefreshedToken stores a session token the SDK refreshed, keeping the
// email on record. The server revoked the previous token, so a token that
// cannot be saved leaves the next command without a session: the user is
// told, since the SDK carries on with the request that renewed it.
func SaveRefreshedToken(token string, expiresAt time.Time) error {
	email := ""
	if tf, err := LoadTokenFile(); err == nil {
		email = tf.Email
	}
	if err := SaveToken(token, email, expiresAt.UTC().Format(time.RFC3339)); err != nil {
		ui.Warning("Could not save the renewed login session",
			fmt.Sprintf("%v\n\nThis command goes on, but the next one will fail until you sign in again with 'secret login'.", err))
		return err
	}
	logging.Module(logging.Log, "auth").Debug("session renewed", "expires_at", expiresAt)
	return nil
}

// ErrSessionExpired is a stored login session past its expiry.
var ErrSessionExpired = errors.New("the login session expired")

// LoadToken reads the login token, and refuses one that has expired
// (ErrSessionExpired).
func LoadToken() (string, error) {
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
			return "", ErrSessionExpired
		}
	}
	return token, nil
}

// LoadTokenFile reads the token file as it is, expired or not.
func LoadTokenFile() (*TokenFile, error) {
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

// RemoveToken deletes the login token.
func RemoveToken() error {
	return os.Remove(tokenPath())
}
