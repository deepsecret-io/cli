// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"strings"
	"testing"

	"github.com/deepsecret-io/cli/internal/config"
	"github.com/deepsecret-io/cli/internal/testutil"
	"github.com/deepsecret-io/deepsecret-go/keys"
	"github.com/deepsecret-io/deepsecret-go/keystore"
)

// The key pair check says which keys a password protects.
func TestDoctorNotesAPasswordKey(t *testing.T) {
	testutil.SetHome(t, t.TempDir())
	save := func(password string) string {
		t.Helper()
		kp, err := keys.Generate()
		if err != nil {
			t.Fatal(err)
		}
		fp, err := keys.Fingerprint(kp)
		if err != nil {
			t.Fatal(err)
		}
		if err := keystore.Save(config.KeysDir(), fp, kp, password); err != nil {
			t.Fatal(err)
		}
		return fp
	}
	locked, open := save("pw"), save("")
	seen := 0
	for _, r := range checkLocalKeys() {
		switch {
		case strings.HasPrefix(r.detail, keys.ShortFingerprint(locked)):
			seen++
			if !r.ok || !strings.Contains(r.detail, "(encrypted)") {
				t.Errorf("password key: %+v", r)
			}
		case strings.HasPrefix(r.detail, keys.ShortFingerprint(open)):
			seen++
			if !r.ok || strings.Contains(r.detail, "(encrypted)") {
				t.Errorf("open key: %+v", r)
			}
		}
	}
	if seen != 2 {
		t.Errorf("saw %d of the 2 keys", seen)
	}
}
