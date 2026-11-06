// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package identity

import (
	"context"
	"fmt"

	"github.com/deepsecret-io/sdk"
	"github.com/deepsecret-io/sdk/api"

	"github.com/deepsecret-io/cli/internal/auth"
	"github.com/deepsecret-io/cli/internal/errs"
	"github.com/deepsecret-io/cli/internal/fingerprint"
	"github.com/deepsecret-io/cli/internal/logging"
)

// FetchRegistered lists the keys registered for the account.
func FetchRegistered(ctx context.Context) ([]sdk.RemoteKey, error) {
	c, err := auth.NewAuthenticatedClient()
	if err != nil {
		return nil, err
	}
	keys, err := c.ListRemoteKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not list your registered keys: %w", errs.APICause(err))
	}
	return keys, nil
}

// Registered is the key among keys whose fingerprint matches fp, or
// nil.
func Registered(keys []sdk.RemoteKey, fp string) *sdk.RemoteKey {
	for i := range keys {
		if fingerprint.Match(keys[i].Fingerprint, fp) {
			return &keys[i]
		}
	}
	return nil
}

// PrimaryLocal is the one of names, the key pairs on this device, that
// is the primary key the server lists, or "" when none is or the server
// cannot be asked.
func PrimaryLocal(ctx context.Context, names []string) string {
	keys, err := FetchRegistered(ctx)
	if err != nil {
		api.Module(logging.Log, "identity").Warn("primary key lookup failed", "error", err)
		return ""
	}
	for _, k := range keys {
		if !k.IsPrimary {
			continue
		}
		for _, n := range names {
			if fingerprint.Match(n, k.Fingerprint) {
				return n
			}
		}
	}
	return ""
}
