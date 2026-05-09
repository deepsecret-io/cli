// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"github.com/deepsecret-io/sdk/crypto"
	"testing"
)

func TestHybridEncryptDecryptRoundtrip(t *testing.T) {
	sender, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("sender keygen: %v", err)
	}
	recipient, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("recipient keygen: %v", err)
	}

	recipientFP, err := crypto.Fingerprint(recipient)
	if err != nil {
		t.Fatal(err)
	}

	recipientPub := &crypto.PublicKeys{
		ED25519:     recipient.ED25519Public,
		X25519:      recipient.X25519Public,
		MLKEM768:    recipient.MLKEM768PK,
		MLDSA65:     recipient.MLDSA65PK,
		Fingerprint: recipientFP,
	}

	plaintext := []byte("hello deepsecret - HPKE post-quantum encrypted!")
	params := crypto.EncryptParams{PayloadType: "message"}

	envelopeData, err := crypto.HybridEncrypt(plaintext, sender, recipientPub, params)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Verify envelope metadata via unmarshal
	env, err := crypto.UnmarshalEnvelope(envelopeData)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if env.Version != crypto.ProtocolVersion {
		t.Fatalf("version: got %q, want %q", env.Version, crypto.ProtocolVersion)
	}
	if env.CipherSuite != crypto.CipherSuite {
		t.Fatalf("cipher suite: got %q, want %q", env.CipherSuite, crypto.CipherSuite)
	}
	if env.PayloadType != "message" {
		t.Fatalf("payload type: got %q, want %q", env.PayloadType, "message")
	}
	if len(env.Enc) == 0 {
		t.Fatal("enc should not be empty")
	}
	if len(env.Ciphertext) == 0 {
		t.Fatal("ciphertext should not be empty")
	}

	// Decrypt
	result, err := crypto.HybridDecrypt(envelopeData, recipient, sender.ED25519Public)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(result.Plaintext) != string(plaintext) {
		t.Fatalf("plaintext mismatch: got %q, want %q", string(result.Plaintext), string(plaintext))
	}
}

func TestDecryptWithCompression(t *testing.T) {
	sender, _ := crypto.GenerateKeyPair()
	recipient, _ := crypto.GenerateKeyPair()
	recipientFP, _ := crypto.Fingerprint(recipient)

	recipientPub := &crypto.PublicKeys{
		ED25519:     recipient.ED25519Public,
		X25519:      recipient.X25519Public,
		MLKEM768:    recipient.MLKEM768PK,
		MLDSA65:     recipient.MLDSA65PK,
		Fingerprint: recipientFP,
	}

	plaintext := []byte("compressed payload with repeated data repeated data repeated data")
	params := crypto.EncryptParams{
		PayloadType: "files",
		Compressed:  true,
		Compression: "zstd",
	}

	envelopeData, err := crypto.HybridEncrypt(plaintext, sender, recipientPub, params)
	if err != nil {
		t.Fatal(err)
	}

	result, err := crypto.HybridDecrypt(envelopeData, recipient, sender.ED25519Public)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Compressed {
		t.Error("expected compressed=true")
	}
	if result.Compression != "zstd" {
		t.Errorf("compression = %q, want %q", result.Compression, "zstd")
	}
	if string(result.Plaintext) != string(plaintext) {
		t.Error("plaintext mismatch")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	sender, _ := crypto.GenerateKeyPair()
	recipient, _ := crypto.GenerateKeyPair()
	wrong, _ := crypto.GenerateKeyPair()
	recipientFP, _ := crypto.Fingerprint(recipient)

	recipientPub := &crypto.PublicKeys{
		ED25519:     recipient.ED25519Public,
		X25519:      recipient.X25519Public,
		MLKEM768:    recipient.MLKEM768PK,
		MLDSA65:     recipient.MLDSA65PK,
		Fingerprint: recipientFP,
	}

	envelopeData, _ := crypto.HybridEncrypt([]byte("secret"), sender, recipientPub, crypto.EncryptParams{PayloadType: "message"})

	_, err := crypto.HybridDecrypt(envelopeData, wrong, sender.ED25519Public)
	if err == nil {
		t.Error("should fail with wrong key")
	}
}

func TestSignatureVerificationFails(t *testing.T) {
	sender, _ := crypto.GenerateKeyPair()
	recipient, _ := crypto.GenerateKeyPair()
	fakeSender, _ := crypto.GenerateKeyPair()
	recipientFP, _ := crypto.Fingerprint(recipient)

	recipientPub := &crypto.PublicKeys{
		ED25519:     recipient.ED25519Public,
		X25519:      recipient.X25519Public,
		MLKEM768:    recipient.MLKEM768PK,
		MLDSA65:     recipient.MLDSA65PK,
		Fingerprint: recipientFP,
	}

	envelopeData, _ := crypto.HybridEncrypt([]byte("secret"), sender, recipientPub, crypto.EncryptParams{PayloadType: "message"})

	_, err := crypto.HybridDecrypt(envelopeData, recipient, fakeSender.ED25519Public)
	if err == nil {
		t.Error("should fail with wrong sender key (signature verification)")
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

func TestSelfEncryptDecrypt(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	fp, _ := crypto.Fingerprint(kp)

	pub := &crypto.PublicKeys{
		ED25519:     kp.ED25519Public,
		X25519:      kp.X25519Public,
		MLKEM768:    kp.MLKEM768PK,
		MLDSA65:     kp.MLDSA65PK,
		Fingerprint: fp,
	}

	msg := "self-encrypted message"
	envelopeData, err := crypto.HybridEncrypt([]byte(msg), kp, pub, crypto.EncryptParams{PayloadType: "message"})
	if err != nil {
		t.Fatal(err)
	}

	result, err := crypto.HybridDecrypt(envelopeData, kp, kp.ED25519Public)
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Plaintext) != msg {
		t.Errorf("got %q, want %q", string(result.Plaintext), msg)
	}
}
