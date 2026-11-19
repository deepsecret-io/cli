// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package identity works with the user's keys: key pair files on this device,
// unlocking them, the keys registered with the server, and safety numbers.
package identity

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/deepsecret-io/deepsecret-go/keys"
	"github.com/deepsecret-io/deepsecret-go/keystore"

	"github.com/deepsecret-io/cli/internal/config"
	"github.com/deepsecret-io/cli/internal/console"
	"github.com/deepsecret-io/cli/internal/errs"
	"github.com/deepsecret-io/cli/internal/fingerprint"
	"github.com/deepsecret-io/cli/internal/prompt"
)

// Exists checks if a key pair file exists on disk.
func Exists(fingerprint string) bool {
	path, ok := keyFile(fingerprint)
	if !ok {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

// ── CLI key wrappers (thin layer over sdk/crypto for interactive password prompts) ──

// SaveKeyPair saves a key pair to the CLI keys directory.
func SaveKeyPair(fingerprint string, kp *keys.Pair, password string) error {
	return keystore.Save(config.KeysDir(), fingerprint, kp, password)
}

// LoadKeyPair loads a key pair: as it is when unprotected, after a
// password prompt, after its security key's PIN and touch, or through AWS
// KMS with no prompt at all.
// The fingerprint may be a prefix that only one key file starts with.
func LoadKeyPair(ctx context.Context, fingerprint string) (*keys.Pair, error) {
	resolved := ResolveFile(fingerprint)
	switch Protection(resolved) {
	case keystore.ProtectionNone:
		return keystore.Load(config.KeysDir(), resolved, "")
	case keystore.ProtectionPassword:
		if err := RequirePasswordTerminal(resolved); err != nil {
			return nil, err
		}
		password, err := prompt.Password(ctx, fmt.Sprintf("Password for key pair %s: ", keys.ShortFingerprint(resolved)))
		if err != nil {
			return nil, err
		}
		return keystore.Load(config.KeysDir(), resolved, password)
	case keystore.ProtectionSecurityKey:
		if err := RequireTerminal(resolved); err != nil {
			return nil, err
		}
		return keystore.Open(ctx, config.KeysDir(), resolved, keystore.Unlock{SecurityKey: SecurityKey()})
	case keystore.ProtectionKMS:
		k, err := KMS(ctx)
		if err != nil {
			return nil, err
		}
		return keystore.Open(ctx, config.KeysDir(), resolved, keystore.Unlock{KMS: k})
	}
	// Unreadable, missing or of a newer version: Load says which.
	return keystore.Load(config.KeysDir(), resolved, "")
}

// keyFile returns the key file of fp, a fingerprint or a prefix of one, or
// false when fp is not one. Fingerprints can come from the server, and
// they name the file, so nothing else passes.
func keyFile(fp string) (string, bool) {
	fp, err := fingerprint.Check(fp)
	if err != nil {
		return "", false
	}
	return filepath.Join(config.KeysDir(), fp+".json"), true
}

// ResolveFile returns the full fingerprint of the key pair on this device
// that fp names, the whole fingerprint or a prefix of 16+ characters that
// only one key starts with (keystore.ResolveFingerprint).
func ResolveFile(fp string) string {
	clean, err := fingerprint.Check(fp)
	if err != nil {
		return fp // not a fingerprint, so it names no file: loading it fails
	}
	return keystore.ResolveFingerprint(config.KeysDir(), clean)
}

// ReadPublicKeys reads the public keys of the key pair named name in the
// keys directory, and computes its fingerprint, without the private keys:
// an encrypted or security-key protected key pair needs nothing to read.
// The public keys must hash to the file's name.
func ReadPublicKeys(name string) (*keys.Pair, string, error) {
	if _, ok := keyFile(name); !ok {
		return nil, "", fmt.Errorf("%q is not named after a key fingerprint", name)
	}
	info, err := keystore.ReadInfo(config.KeysDir(), name)
	if err != nil {
		return nil, "", errs.PathCause(err)
	}
	return &keys.Pair{
		ED25519Public: info.Public.ED25519,
		X25519Public:  info.Public.X25519,
		MLKEM768PK:    info.Public.MLKEM768,
		MLDSA65PK:     info.Public.MLDSA65,
	}, info.Fingerprint, nil
}

// ResolveName finds the key pair on this device that fpOrPrefix,
// a fingerprint or a prefix of 16+ characters of one, names, and returns
// its name in the keys directory.
func ResolveName(fpOrPrefix string) (string, error) {
	names, err := List()
	if err != nil {
		return "", fmt.Errorf("could not list the key pairs on this device: %w", err)
	}
	var matches []string
	for _, n := range names {
		if n == fpOrPrefix {
			return n, nil
		}
		if strings.HasPrefix(n, fpOrPrefix) {
			matches = append(matches, n)
		}
	}
	switch len(matches) {
	case 0:
		return "", errs.WithDetail(fmt.Errorf("no key pair %s on this device", fpOrPrefix), "List them with: secret identity list")
	case 1:
		return matches[0], nil
	}
	for i, m := range matches {
		matches[i] = console.Safe(m)
	}
	return "", errs.WithDetail(fmt.Errorf("%s matches %d key pairs on this device", fpOrPrefix, len(matches)),
		"Give more of the fingerprint:\n  "+strings.Join(matches, "\n  "))
}

// List returns fingerprints of all locally stored key pairs.
func List() ([]string, error) {
	return keystore.List(config.KeysDir())
}

// FindLocal returns the full local-keystore fingerprint that
// matches expectedFP (case-insensitive exact match), or "" if no local key
// has that fingerprint. Used by decrypt to auto-select the right identity
// when the user's primary key is no longer the recipient.
func FindLocal(expectedFP string) string {
	if expectedFP == "" {
		return ""
	}
	keyList, err := List()
	if err != nil {
		return ""
	}
	for _, fp := range keyList {
		if strings.EqualFold(fp, expectedFP) {
			return fp
		}
	}
	return ""
}
