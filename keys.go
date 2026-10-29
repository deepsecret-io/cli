// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/deepsecret-io/sdk/crypto"
)

// ── Fingerprint comparison ───────────────────────────────────────────────────

// fingerprintMatch compares two fingerprints that may be different lengths.
// The server stores 32-char (truncated) fingerprints while the SDK now produces
// 64-char (full SHA-256) fingerprints. This matches if either is a prefix of
// the other, or they are exactly equal.
func fingerprintMatch(a, b string) bool {
	if a == b {
		return true
	}
	if len(a) < len(b) {
		return len(a) >= 16 && b[:len(a)] == a
	}
	return len(b) >= 16 && a[:len(b)] == b
}

// ── CLI key wrappers (thin layer over sdk/crypto for interactive password prompts) ──

// saveKeyPair saves a key pair to the CLI keys directory.
func saveKeyPair(fingerprint string, kp *crypto.KeyPair, password string) error {
	return crypto.SaveKeyPairTo(keysDir(), fingerprint, kp, password)
}

// loadKeyPair loads a key pair, prompting for password if encrypted.
// If the fingerprint doesn't match a file exactly, it tries prefix matching
// (handles server-side 32-char fingerprints vs local 64-char filenames).
func loadKeyPair(fingerprint string) (*crypto.KeyPair, error) {
	resolved := resolveKeystoreFingerprint(fingerprint)
	kp, err := crypto.LoadKeyPairFrom(keysDir(), resolved, "")
	if err != nil && isKeyPairEncrypted(resolved) {
		password, perr := readPassword("Enter key password: ")
		if perr != nil {
			return nil, perr
		}
		return crypto.LoadKeyPairFrom(keysDir(), resolved, password)
	}
	return kp, err
}

// keyFile returns the key file of fp, a fingerprint or a prefix of one, or
// false when fp is not one. Fingerprints can come from the server, and
// they name the file, so nothing else passes.
func keyFile(fp string) (string, bool) {
	fp, err := checkFingerprint(fp)
	if err != nil {
		return "", false
	}
	return filepath.Join(keysDir(), fp+".json"), true
}

// resolveKeystoreFingerprint resolves a possibly-truncated fingerprint to the
// full filename in the keys directory. This handles the case where the server
// stores 32-char fingerprints but local files use 64-char names.
func resolveKeystoreFingerprint(fp string) string {
	clean, err := checkFingerprint(fp)
	if err != nil {
		return fp // not a fingerprint, so it names no file: loading it fails
	}
	fp = clean
	// Try exact match first
	if _, err := os.Stat(filepath.Join(keysDir(), fp+".json")); err == nil {
		return fp
	}
	// Try prefix match against local key files
	entries, err := os.ReadDir(keysDir())
	if err != nil {
		return fp
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		name := e.Name()[:len(e.Name())-5]
		if len(fp) >= 16 && len(name) > len(fp) && name[:len(fp)] == fp {
			return name
		}
	}
	return fp // no match found, return as-is (will error on load)
}

// isKeyPairEncrypted checks if a key pair file is password-encrypted.
func isKeyPairEncrypted(fingerprint string) bool {
	path, ok := keyFile(fingerprint)
	if !ok {
		return false
	}
	data, err := os.ReadFile(path) // #nosec G304 -- keyFile accepts hex fingerprints only, so path stays in the keys directory.
	if err != nil {
		return false
	}
	var kp struct {
		Encrypted bool `json:"encrypted"`
	}
	if err := json.Unmarshal(data, &kp); err != nil {
		return false
	}
	return kp.Encrypted
}

// listKeyPairs returns fingerprints of all locally stored key pairs.
func listKeyPairs() ([]string, error) {
	return crypto.ListLocalKeysIn(keysDir())
}

// findLocalKeyByFingerprint returns the full local-keystore fingerprint that
// matches expectedFP (case-insensitive exact match), or "" if no local key
// has that fingerprint. Used by decrypt to auto-select the right identity
// when the user's primary key is no longer the recipient.
func findLocalKeyByFingerprint(expectedFP string) string {
	if expectedFP == "" {
		return ""
	}
	keys, err := listKeyPairs()
	if err != nil {
		return ""
	}
	for _, fp := range keys {
		if strings.EqualFold(fp, expectedFP) {
			return fp
		}
	}
	return ""
}
