// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"testing"

	"github.com/deepsecret-io/sdk/crypto"
)

const testRevisionID = "4f9c1e5a-8b2d-4c3e-9f1a-2b3c4d5e6f70"

const testSecretName = "db-password"

type testParty struct {
	kp  *crypto.KeyPair
	fp  string
	pub *crypto.PublicKeys
}

func newTestParty(t *testing.T) testParty {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	fp, err := crypto.Fingerprint(kp)
	if err != nil {
		t.Fatal(err)
	}
	return testParty{kp: kp, fp: fp, pub: &crypto.PublicKeys{
		ED25519:     kp.ED25519Public,
		X25519:      kp.X25519Public,
		MLKEM768:    kp.MLKEM768PK,
		MLDSA65:     kp.MLDSA65PK,
		Fingerprint: fp,
	}}
}

// sealFor seals plaintext once for every recipient.
func sealFor(t *testing.T, plaintext []byte, sender testParty, p crypto.SealParams, recipients ...testParty) ([]byte, *crypto.Sealed) {
	t.Helper()
	pubs := make([]*crypto.PublicKeys, len(recipients))
	for i, r := range recipients {
		pubs[i] = r.pub
	}
	payload, sealed, err := crypto.SealBytes(plaintext, sender.kp, pubs, p)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return payload, sealed
}

// openAs opens the revision as r with r's own wrap and decrypts payload.
func openAs(sealed *crypto.Sealed, payload []byte, r testParty, senderED25519 string) ([]byte, *crypto.Manifest, error) {
	wrap, _ := sealed.Wrap(r.fp)
	opened, err := crypto.Open(sealed.ManifestData, wrap, r.kp, crypto.OpenParams{RevisionID: testRevisionID, SecretName: testSecretName, SenderED25519: senderED25519})
	if err != nil {
		return nil, nil, err
	}
	defer opened.Close()
	plaintext, err := opened.Decrypt(payload)
	return plaintext, opened.Manifest, err
}

func TestSealOpenRoundtrip(t *testing.T) {
	sender, alice, bob := newTestParty(t), newTestParty(t), newTestParty(t)
	plaintext := []byte("hello deepsecret - one payload, every recipient")
	payload, sealed := sealFor(t, plaintext, sender, crypto.SealParams{RevisionID: testRevisionID, SecretName: testSecretName, PayloadType: "message"}, alice, bob)

	m, err := crypto.UnmarshalManifest(sealed.ManifestData)
	if err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	if m.Version != crypto.ProtocolVersion {
		t.Fatalf("version: got %q, want %q", m.Version, crypto.ProtocolVersion)
	}
	if m.CipherSuite != crypto.CipherSuite {
		t.Fatalf("cipher suite: got %q, want %q", m.CipherSuite, crypto.CipherSuite)
	}
	if m.PayloadType != "message" || len(m.Recipients) != 2 || m.CiphertextSize != int64(len(payload)) {
		t.Fatalf("manifest: %+v", m)
	}

	for _, r := range []testParty{alice, bob} {
		got, _, err := openAs(sealed, payload, r, sender.kp.ED25519Public)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if string(got) != string(plaintext) {
			t.Fatalf("plaintext mismatch: got %q, want %q", got, plaintext)
		}
	}
}

func TestDecryptWithCompression(t *testing.T) {
	sender, recipient := newTestParty(t), newTestParty(t)
	plaintext := []byte("compressed payload with repeated data repeated data repeated data")
	payload, sealed := sealFor(t, plaintext, sender, crypto.SealParams{
		RevisionID:  testRevisionID,
		SecretName:  testSecretName,
		PayloadType: "files",
		Compressed:  true,
		Compression: "zstd",
	}, recipient)

	got, m, err := openAs(sealed, payload, recipient, sender.kp.ED25519Public)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Compressed {
		t.Error("expected compressed=true")
	}
	if m.Compression != "zstd" {
		t.Errorf("compression = %q, want %q", m.Compression, "zstd")
	}
	if string(got) != string(plaintext) {
		t.Error("plaintext mismatch")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	sender, recipient, wrong := newTestParty(t), newTestParty(t), newTestParty(t)
	_, sealed := sealFor(t, []byte("secret"), sender, crypto.SealParams{RevisionID: testRevisionID, SecretName: testSecretName, PayloadType: "message"}, recipient)

	wrap, _ := sealed.Wrap(recipient.fp)
	if _, err := crypto.Open(sealed.ManifestData, wrap, wrong.kp, crypto.OpenParams{RevisionID: testRevisionID, SecretName: testSecretName}); err == nil {
		t.Error("should fail with a key that is not a recipient")
	}
}

func TestSignatureVerificationFails(t *testing.T) {
	sender, recipient, fakeSender := newTestParty(t), newTestParty(t), newTestParty(t)
	payload, sealed := sealFor(t, []byte("secret"), sender, crypto.SealParams{RevisionID: testRevisionID, SecretName: testSecretName, PayloadType: "message"}, recipient)

	if _, _, err := openAs(sealed, payload, recipient, fakeSender.kp.ED25519Public); err == nil {
		t.Error("should fail with wrong expected sender key")
	}
}

func TestKeyFingerprint(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()

	fp1, err := crypto.Fingerprint(kp)
	if err != nil {
		t.Fatal(err)
	}
	fp2, err := crypto.Fingerprint(kp)
	if err != nil {
		t.Fatal(err)
	}
	if fp1 != fp2 {
		t.Error("same key should produce same fingerprint")
	}

	fp3, err := crypto.FingerprintFromPubs(kp.ED25519Public, kp.X25519Public, kp.MLKEM768PK, kp.MLDSA65PK)
	if err != nil {
		t.Fatal(err)
	}
	if fp1 != fp3 {
		t.Error("Fingerprint and FingerprintFromPubs should match")
	}

	kp2, _ := crypto.GenerateKeyPair()
	fp4, _ := crypto.Fingerprint(kp2)
	if fp1 == fp4 {
		t.Error("different keys should have different fingerprints")
	}
}

func TestKeyBundleSignVerify(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()

	edSig, mldsaSig, err := crypto.SignKeyBundle(kp)
	if err != nil {
		t.Fatal(err)
	}

	if err := crypto.VerifyKeyBundleSignature(kp.ED25519Public, kp.X25519Public, kp.MLKEM768PK, kp.MLDSA65PK, edSig, mldsaSig); err != nil {
		t.Errorf("valid signature should verify: %v", err)
	}

	kp2, _ := crypto.GenerateKeyPair()
	if err := crypto.VerifyKeyBundleSignature(kp2.ED25519Public, kp.X25519Public, kp.MLKEM768PK, kp.MLDSA65PK, edSig, mldsaSig); err == nil {
		t.Error("mismatched key should fail verification")
	}
}

// A self-send lists only the sender, who then holds the one wrap.
func TestSelfEncryptDecrypt(t *testing.T) {
	self := newTestParty(t)
	msg := "self-encrypted message"
	payload, sealed := sealFor(t, []byte(msg), self, crypto.SealParams{RevisionID: testRevisionID, SecretName: testSecretName, PayloadType: "message"}, self)
	if len(sealed.Wraps) != 1 {
		t.Fatalf("want a single wrap, got %d", len(sealed.Wraps))
	}

	got, _, err := openAs(sealed, payload, self, self.kp.ED25519Public)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != msg {
		t.Errorf("got %q, want %q", got, msg)
	}
}
