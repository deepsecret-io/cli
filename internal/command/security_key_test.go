// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	sdkidentity "github.com/deepsecret-io/deepsecret-go/identity"
	"github.com/deepsecret-io/deepsecret-go/keys"
	"github.com/deepsecret-io/deepsecret-go/keystore"
	"github.com/deepsecret-io/deepsecret-go/trust"

	"github.com/deepsecret-io/cli/internal/auth"
	"github.com/deepsecret-io/cli/internal/config"
	"github.com/deepsecret-io/cli/internal/identity"
	"github.com/deepsecret-io/cli/internal/testutil"
)

// fakeSecurityKey is a FIDO2 key in memory.
type fakeSecurityKey struct{ secrets map[string][]byte }

func (k *fakeSecurityKey) out(id, input []byte) []byte {
	salt := keystore.PRFSalt(input)
	m := hmac.New(sha256.New, k.secrets[hex.EncodeToString(id)])
	m.Write(salt[:])
	return m.Sum(nil)
}

func (k *fakeSecurityKey) Enroll(_ context.Context, req keystore.EnrollRequest) (*keystore.EnrollResult, error) {
	id, secret := make([]byte, 32), make([]byte, 32)
	_, _ = rand.Read(id)
	_, _ = rand.Read(secret)
	k.secrets[hex.EncodeToString(id)] = secret
	return &keystore.EnrollResult{CredentialID: id, Device: "Fake key", Output: k.out(id, req.PRFInput)}, nil
}

func (k *fakeSecurityKey) Derive(_ context.Context, req keystore.DeriveRequest) (*keystore.DeriveResult, error) {
	for _, c := range req.Credentials {
		if _, ok := k.secrets[hex.EncodeToString(c.ID)]; ok {
			return &keystore.DeriveResult{CredentialID: c.ID, Output: k.out(c.ID, c.PRFInput)}, nil
		}
	}
	return nil, keystore.ErrNoSecurityKey
}

// protectedKeyPair stores a new key pair protected by a fake security key
// and a recovery code in the CLI keys directory.
func protectedKeyPair(t *testing.T) (*keys.Pair, string) {
	t.Helper()
	kp, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e, err := keystore.NewSecurityKeyFile(config.KeysDir(), kp)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if _, err := e.AddSecurityKey(context.Background(), &fakeSecurityKey{secrets: map[string][]byte{}}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.SetRecoveryCode(); err != nil {
		t.Fatal(err)
	}
	if err := e.Commit(false); err != nil {
		t.Fatal(err)
	}
	return kp, e.Fingerprint()
}

// A security-key protected key pair reads like any other for its public
// keys, and is told apart from a password-protected one.
func TestSecurityKeyProtectedKeyFile(t *testing.T) {
	testutil.SetHome(t, t.TempDir())
	kp, fp := protectedKeyPair(t)
	if p := identity.Protection(fp); p != keystore.ProtectionSecurityKey {
		t.Fatalf("keyProtection = %q", p)
	}
	if identity.IsEncrypted(fp) {
		t.Error("a security-key file was taken for a password-protected one")
	}
	pub, got, err := identity.ReadPublicKeys(fp)
	if err != nil || got != fp || pub.MLDSA65PK != kp.MLDSA65PK {
		t.Fatalf("readPublicKeys: %+v, %q, %v", pub, got, err)
	}
	if c, ok := checkSecurityKeys(); !ok || c.name != "Security keys" {
		t.Errorf("doctor does not report security key support: %+v", c)
	}
}

// Users without a security key see nothing new: doctor says nothing, an
// unprotected key needs nothing, and --recovery-code is refused.
func TestNoSecurityKeyNoChange(t *testing.T) {
	testutil.SetHome(t, t.TempDir())
	kp, _ := keys.Generate()
	fp, _ := keys.Fingerprint(kp)
	if err := identity.SaveKeyPair(fp, kp, ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := checkSecurityKeys(); ok {
		t.Error("doctor reports security keys with none in use")
	}
	u, err := commandUnlock(context.Background(), nil, fp, false)
	if err != nil || u.Password != "" || u.SecurityKey != nil || u.RecoveryCode != "" {
		t.Errorf("commandUnlock on an unprotected key = %+v, %v", u, err)
	}
	if _, err := commandUnlock(context.Background(), nil, fp, true); err == nil || !strings.Contains(err.Error(), "not protected by a security key") {
		t.Errorf("--recovery-code on an unprotected key: %v", err)
	}
}

func TestCheckSecondWay(t *testing.T) {
	if err := checkSecondWay(false, false, false); err == nil {
		t.Error("no second way in and no waiver was accepted")
	}
	for _, c := range [][3]bool{{true, false, false}, {false, true, false}, {false, false, true}} {
		if err := checkSecondWay(c[0], c[1], c[2]); err != nil {
			t.Errorf("checkSecondWay%v: %v", c, err)
		}
	}
}

// The security key label: read from the key file on this device, for a
// full fingerprint only, and from the server's label for a key elsewhere.
func TestSecurityKeyLabel(t *testing.T) {
	testutil.SetHome(t, t.TempDir())
	_, protected := protectedKeyPair(t)
	kp, _ := keys.Generate()
	plain, _ := keys.Fingerprint(kp)
	if err := identity.SaveKeyPair(plain, kp, ""); err != nil {
		t.Fatal(err)
	}
	elsewhere := strings.Repeat("ab", 32)

	for fp, want := range map[string]string{protected: " (security key)", plain: "", protected[:16]: "", elsewhere: "", "": ""} {
		if got := identity.ProtectionNote(fp); got != want {
			t.Errorf("ProtectionNote(%.16s) = %q, want %q", fp, got, want)
		}
	}
	cases := []struct {
		k    sdkidentity.Key
		want string
	}{
		{sdkidentity.Key{Fingerprint: protected}, "security-key"},
		{sdkidentity.Key{Fingerprint: plain, SecurityKey: true}, ""}, // the key file here wins
		{sdkidentity.Key{Fingerprint: elsewhere, SecurityKey: true}, "security-key (reported)"},
		{sdkidentity.Key{Fingerprint: elsewhere}, ""},
	}
	for _, c := range cases {
		if got := identity.RemoteLabel(c.k); got != c.want {
			t.Errorf("remoteKeyLabel(%.16s, label %v) = %q, want %q", c.k.Fingerprint, c.k.SecurityKey, got, c.want)
		}
	}
}

// identity sync on a key registered from another device records the
// account signed in as yours on this device with it, without unlocking the
// key pair or uploading anything: a secret it signed for that account then
// opens here instead of being refused as from an account this device does
// not know as yours.
func TestSyncRegisteredKeyRecordsTheAccount(t *testing.T) {
	testutil.SetHome(t, t.TempDir())
	_, fp := protectedKeyPair(t)
	const bob = "bob@example.com"
	var mu sync.Mutex
	var writes []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			mu.Lock()
			writes = append(writes, r.Method+" "+r.URL.Path)
			mu.Unlock()
		}
		var data any = map[string]any{}
		switch r.URL.Path {
		case "/api/v1/identities":
			data = map[string]any{"keys": []map[string]any{{"id": "k1", "fingerprint": fp, "is_primary": true, "security_key": true}}}
		case "/api/v1/actors/me":
			data = map[string]any{"actor": map[string]any{"id": "actor-1", "email": bob},
				"membership": map[string]any{"org_id": "org-1", "role": "owner"}}
		case "/api/v1/orgs":
			data = []any{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": data})
	}))
	defer srv.Close()
	c, err := auth.NewClient(srv.URL, "test-key")
	if err != nil {
		t.Fatal(err)
	}

	out := testutil.StderrOf(t, func() {
		if err := syncRegisteredKey(context.Background(), c, &sdkidentity.Key{ID: "k1", Fingerprint: fp, IsPrimary: true, SecurityKey: true}, fp); err != nil {
			t.Error(err)
		}
	})
	if !strings.Contains(out, "Key "+keys.ShortFingerprint(fp)+" is registered") {
		t.Errorf("%q does not say the key is registered", out)
	}
	known, err := c.Trust.List(bob)
	if err != nil {
		t.Fatal(err)
	}
	if len(known) != 1 || known[0].Fingerprint != fp || known[0].State != trust.Own {
		t.Fatalf("bob's known keys %+v, want the key pair here as the user's own", known)
	}
	if len(writes) != 0 {
		t.Errorf("requests %q, want reads only", writes)
	}
}

// identity sync on a registered key sets its label from the key file,
// and sends nothing when the label is already right.
func TestRefreshSecurityKeyLabel(t *testing.T) {
	testutil.SetHome(t, t.TempDir())
	_, fp := protectedKeyPair(t)
	var mu sync.Mutex
	var puts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		puts = append(puts, r.Method+" "+r.URL.Path+" "+strings.TrimSpace(string(body)))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"success":true,"data":{"message":"Key pair updated"}}`)
	}))
	defer srv.Close()
	c, err := auth.NewClient(srv.URL, "test-key")
	if err != nil {
		t.Fatal(err)
	}

	if err := refreshSecurityKeyLabel(context.Background(), c, &sdkidentity.Key{ID: "k1", Fingerprint: fp, IsPrimary: true}, fp); err != nil {
		t.Fatal(err)
	}
	if err := refreshSecurityKeyLabel(context.Background(), c, &sdkidentity.Key{ID: "k1", Fingerprint: fp, IsPrimary: true, SecurityKey: true}, fp); err != nil {
		t.Fatal(err)
	}
	want := `PUT /api/v1/identities/k1/security-key {"security_key":true}`
	if len(puts) != 1 || puts[0] != want {
		t.Errorf("requests = %q, want one: %s", puts, want)
	}
}
