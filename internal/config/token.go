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
	"github.com/deepsecret-io/cli/internal/safefile"
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
	if err := safefile.MkdirPrivate(Dir()); err != nil {
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
// (ErrSessionExpired) or, on Windows, a token file someone else may open
// (safefile.ErrNotPrivate).
func LoadToken() (string, error) {
	data, err := safefile.ReadPrivate(tokenPath())
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

// LoadTokenFile reads the token file as it is, expired or not, and on
// Windows refuses one someone else may open (safefile.ErrNotPrivate).
func LoadTokenFile() (*TokenFile, error) {
	return parseTokenFile(safefile.ReadPrivate(tokenPath()))
}

// LoadTokenFileToRevoke reads the token file as LoadTokenFile does, but
// also when someone else may open it: logout revokes and removes the
// token, which is what an exposed one needs. Sending a token someone else
// planted to be revoked only ends their session.
func LoadTokenFileToRevoke() (*TokenFile, error) {
	return parseTokenFile(os.ReadFile(tokenPath()))
}

// parseTokenFile decodes the token file read as data, or returns the error
// reading it gave.
func parseTokenFile(data []byte, err error) (*TokenFile, error) {
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
