// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build windows

package identity

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deepsecret-io/deepsecret-go/keys"

	"github.com/deepsecret-io/cli/internal/config"
	"github.com/deepsecret-io/cli/internal/testutil"
)

// Key files are written and read by the SDK version go.mod requires, so
// this checks that version: the keys folder and every key file are
// private to the user, and a key file someone else may open is refused.
// An SDK without owner-only ACLs on Windows fails it, which keeps a
// Windows release from shipping with one.
func TestKeyFilesArePrivate(t *testing.T) {
	testutil.SetHome(t, t.TempDir())
	kp, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	fp, err := keys.Fingerprint(kp)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveKeyPair(fp, kp, ""); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(config.KeysDir(), fp+".json")
	testutil.AssertPrivate(t, config.Dir())
	testutil.AssertPrivate(t, config.KeysDir())
	testutil.AssertPrivate(t, path)
	if _, err := LoadKeyPair(context.Background(), fp); err != nil {
		t.Fatalf("a private key file: %v", err)
	}

	testutil.Expose(t, path)
	if _, err := LoadKeyPair(context.Background(), fp); err == nil || !strings.Contains(err.Error(), "open to other users") {
		t.Errorf("an exposed key file: %v", err)
	}
}
