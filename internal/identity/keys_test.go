// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package identity

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deepsecret-io/deepsecret-go/keys"

	"github.com/deepsecret-io/cli/internal/config"
)

// Key fingerprints name files in the keys directory, and the server
// supplies some of them: one that is not hex is never used as a path.
func TestKeyFileRefusesPaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(config.KeysDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	// An encrypted key file outside the keys directory, where a hostile
	// fingerprint could point.
	if err := os.WriteFile(filepath.Join(home, "planted.json"), []byte(`{"encrypted":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, fp := range []string{"../../planted", "../planted", "..", "", "0123456789abcdef/../../planted"} {
		if _, ok := keyFile(fp); ok {
			t.Errorf("keyFile(%q) accepted a path", fp)
		}
		if IsEncrypted(fp) {
			t.Errorf("isKeyPairEncrypted(%q) read a file outside the keys directory", fp)
		}
		if Exists(fp) {
			t.Errorf("existsKeyPair(%q) found a file outside the keys directory", fp)
		}
		if got := ResolveFile(fp); got != fp {
			t.Errorf("resolveKeystoreFingerprint(%q) = %q", fp, got)
		}
		if _, err := LoadKeyPair(context.Background(), fp); err == nil {
			t.Errorf("LoadKeyPair(%q) loaded a key", fp)
		}
	}
	if path, ok := keyFile(strings.Repeat("AB", 32)); !ok || path != filepath.Join(config.KeysDir(), strings.Repeat("ab", 32)+".json") {
		t.Errorf("keyFile of a full fingerprint: %q, %v", path, ok)
	}
}

// identity show reads the public keys of an encrypted key pair without
// its password.
func TestReadPublicKeysNeedsNoPassword(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	kp, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	fp, err := keys.Fingerprint(kp)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveKeyPair(fp, kp, "correct horse"); err != nil {
		t.Fatal(err)
	}
	pub, got, err := ReadPublicKeys(fp)
	if err != nil || got != fp || pub.ED25519Public != kp.ED25519Public || !IsEncrypted(fp) {
		t.Fatalf("readPublicKeys: %q, %v", got, err)
	}
	if _, _, err := ReadPublicKeys("../keys"); err == nil {
		t.Fatal("a path was read as a key pair")
	}
}
