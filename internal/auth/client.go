// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package auth picks the credential a command uses and builds the SDK client
// that sends it.
package auth

import (
	"github.com/deepsecret-io/sdk"

	"github.com/deepsecret-io/cli/internal/config"
)

// NewClient creates an SDK client for CLI use.
//
// The client takes the CLI's keys directory as this device's, so only the key
// pairs the CLI keeps pass as the user's own.
func NewClient(baseURL, apiKey string, opts ...sdk.Option) (*sdk.Client, error) {
	return sdk.NewClient(baseURL, apiKey, append([]sdk.Option{sdk.WithKeysDir(config.KeysDir())}, opts...)...)
}
