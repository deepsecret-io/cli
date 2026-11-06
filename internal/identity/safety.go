// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/deepsecret-io/sdk"
	"github.com/deepsecret-io/sdk/crypto"
)

// LocalPrimaryKey is the fingerprint of your primary key, computed from
// its key pair on this device. The server's listing alone is not enough:
// a server that listed a key of its own as yours, and to them as yours
// too, would get matching numbers.
func LocalPrimaryKey(ctx context.Context) (string, error) {
	names, err := List()
	if err != nil {
		return "", fmt.Errorf("could not list the key pairs on this device: %w", err)
	}
	var local []string
	for _, n := range names {
		if _, fp, err := ReadPublicKeys(n); err == nil {
			local = append(local, fp)
		}
	}
	if len(local) == 0 {
		return "", errors.New("there is no key pair on this device")
	}
	registered, err := FetchRegistered(ctx)
	if err != nil {
		return "", err
	}
	return PrimaryOnDevice(registered, local)
}

// PrimaryOnDevice is the primary key among registered when it is one of
// local, the fingerprints computed from the key pairs on this device.
func PrimaryOnDevice(registered []sdk.RemoteKey, local []string) (string, error) {
	for _, k := range registered {
		if !k.IsPrimary {
			continue
		}
		for _, fp := range local {
			if strings.EqualFold(fp, k.Fingerprint) {
				return fp, nil
			}
		}
		return "", errors.New("your primary key is not on this device")
	}
	return "", errors.New("you have no primary key (choose one with: secret identity set-primary <fingerprint>)")
}

// SafetyNumber is the safety number of one key of yours: six groups
// of five digits on one line.
func SafetyNumber(fp string) (string, error) {
	n, err := crypto.SafetyNumber(strings.ToLower(fp))
	if err != nil {
		return "", err
	}
	return crypto.GroupDigits(n), nil
}

// PairSafetyRows is the safety number of your key own and their key
// theirs in three rows of four groups of five digits, to read aloud.
func PairSafetyRows(own, theirs string) ([]string, error) {
	n, err := crypto.PairSafetyNumber(strings.ToLower(own), strings.ToLower(theirs))
	if err != nil {
		return nil, err
	}
	groups := strings.Fields(crypto.GroupDigits(n))
	var rows []string
	for i := 0; i < len(groups); i += 4 {
		rows = append(rows, strings.Join(groups[i:min(i+4, len(groups))], " "))
	}
	return rows, nil
}
