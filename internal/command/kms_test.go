// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdkidentity "github.com/deepsecret-io/deepsecret-go/identity"
	"github.com/deepsecret-io/deepsecret-go/keys"
	"github.com/deepsecret-io/deepsecret-go/keystore"

	"github.com/deepsecret-io/cli/internal/config"
	"github.com/deepsecret-io/cli/internal/errs"
	"github.com/deepsecret-io/cli/internal/identity"
	"github.com/deepsecret-io/cli/internal/testutil"
)

const (
	testKMSARN     = "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
	testKMSAccount = "6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f"
)

// fakeKMS is one symmetric KMS key in memory.
type fakeKMS struct{ key []byte }

func (k fakeKMS) DescribeKey(context.Context, string) (*keystore.KMSKey, error) {
	return &keystore.KMSKey{ARN: testKMSARN, Spec: keystore.KMSKeySpecSymmetric, Usage: keystore.KMSKeyUsageEncrypt,
		State: keystore.KMSKeyStateEnabled, Manager: keystore.KMSKeyManagerCustomer}, nil
}

func (k fakeKMS) gcm() cipher.AEAD {
	block, _ := aes.NewCipher(k.key)
	g, _ := cipher.NewGCM(block)
	return g
}

func (k fakeKMS) Encrypt(_ context.Context, _ string, c map[string]string, p []byte) (*keystore.KMSResult, error) {
	nonce := make([]byte, 12)
	_, _ = rand.Read(nonce)
	return &keystore.KMSResult{KeyARN: testKMSARN, Data: k.gcm().Seal(nonce, nonce, p, []byte(c[keystore.KMSContextKeySlot]))}, nil
}

func (k fakeKMS) Decrypt(_ context.Context, _ string, c map[string]string, ct []byte) (*keystore.KMSResult, error) {
	p, err := k.gcm().Open(nil, ct[:12], ct[12:], []byte(c[keystore.KMSContextKeySlot]))
	if err != nil {
		return nil, keystore.ErrKMSMismatch
	}
	return &keystore.KMSResult{KeyARN: testKMSARN, Data: p}, nil
}

// isolateAWS points the AWS SDK at an empty configuration with no
// credentials, so no test reads the developer's AWS setup or reaches AWS.
func isolateAWS(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	for k, v := range map[string]string{
		"AWS_CONFIG_FILE": filepath.Join(dir, "config"), "AWS_SHARED_CREDENTIALS_FILE": filepath.Join(dir, "credentials"),
		"AWS_PROFILE": "", "AWS_ACCESS_KEY_ID": "", "AWS_SECRET_ACCESS_KEY": "", "AWS_SESSION_TOKEN": "",
		"AWS_ROLE_ARN": "", "AWS_WEB_IDENTITY_TOKEN_FILE": "", "AWS_CONTAINER_CREDENTIALS_FULL_URI": "",
		"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "", "AWS_EC2_METADATA_DISABLED": "true", "AWS_REGION": "",
	} {
		t.Setenv(k, v)
	}
}

// kmsKeyPair stores a new key pair protected by a fake KMS key and a
// recovery code in the CLI keys directory.
func kmsKeyPair(t *testing.T) (*keys.Pair, string) {
	t.Helper()
	kp, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e, err := keystore.NewKMSKeyFile(config.KeysDir(), kp)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	if _, err := e.AddKMS(context.Background(), fakeKMS{key}, testKMSARN, testKMSAccount, ""); err != nil {
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

// A KMS key pair reads like any other for its public keys, and is labelled
// as KMS-protected everywhere a protection shows.
func TestKMSKeyPairLabels(t *testing.T) {
	testutil.SetHome(t, t.TempDir())
	kp, fp := kmsKeyPair(t)
	if p := identity.Protection(fp); p != keystore.ProtectionKMS {
		t.Fatalf("Protection = %q", p)
	}
	if identity.IsEncrypted(fp) {
		t.Error("a KMS file was taken for a password-protected one")
	}
	pub, got, err := identity.ReadPublicKeys(fp)
	if err != nil || got != fp || pub.MLDSA65PK != kp.MLDSA65PK {
		t.Fatalf("ReadPublicKeys: %v, %v", got, err)
	}
	if n := identity.ProtectionNote(fp); n != " (AWS KMS)" {
		t.Errorf("ProtectionNote = %q", n)
	}
	if l := identity.RemoteLabel(sdkidentity.Key{Fingerprint: fp}); l != "aws-kms" {
		t.Errorf("RemoteLabel = %q", l)
	}
	if tags := strings.Join(keyTags(keystore.ProtectionKMS, nil, true), ","); tags != "aws-kms,local-only" {
		t.Errorf("keyTags = %q", tags)
	}
	if _, ok := checkSecurityKeys(); ok {
		t.Error("doctor reports security keys for a KMS key pair")
	}
}

// A KMS key pair unlocks with no terminal and no prompt, and never reaches
// a password or security key branch; the commands for security keys
// refuse it by name.
func TestKMSUnlockRouting(t *testing.T) {
	testutil.SetHome(t, t.TempDir())
	isolateAWS(t)
	_, fp := kmsKeyPair(t)
	u, err := commandUnlock(context.Background(), nil, fp, false)
	if err != nil || u.KMS == nil || u.Password != "" || u.SecurityKey != nil || u.RecoveryCode != "" {
		t.Fatalf("commandUnlock = %+v, %v", u, err)
	}
	if _, err := unlockForEdit(context.Background(), fp, false); err == nil || !strings.Contains(err.Error(), "protected by AWS KMS") {
		t.Errorf("security-key command on a KMS key pair: %v", err)
	}
	if err := runRoot("identity", "security-key", "protect", "-i", fp, "--single"); err == nil || !strings.Contains(err.Error(), "never both") {
		t.Errorf("security-key protect on a KMS key pair: %v", err)
	}
	if err := runRoot("identity", "kms", "protect", "-i", fp, "--kms-arn", testKMSARN, "--single"); err == nil || !strings.Contains(err.Error(), "already protected by AWS KMS") {
		t.Errorf("kms protect twice: %v", err)
	}
	// A KMS command on a key pair that is not KMS-protected says so.
	kp, _ := keys.Generate()
	plain, _ := keys.Fingerprint(kp)
	if err := identity.SaveKeyPair(plain, kp, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := unlockKMSForEdit(context.Background(), plain, false); err == nil || !strings.Contains(err.Error(), "not protected by AWS KMS") {
		t.Errorf("kms command on a plain key pair: %v", err)
	}
	if _, err := commandUnlock(context.Background(), nil, plain, true); err == nil || !strings.Contains(err.Error(), "no recovery code") {
		t.Errorf("--recovery-code on a plain key pair: %v", err)
	}
}

func TestCheckKMSWays(t *testing.T) {
	one, two := []string{testKMSARN}, []string{testKMSARN, "arn:aws:kms:us-east-1:111122223333:key/00000000-0000-4000-8000-000000000001"}
	for _, c := range []struct {
		ids              []string
		recovery, single bool
		ok               bool
	}{
		{nil, false, true, false},
		{one, false, false, false},
		{one, true, false, true},
		{one, false, true, true},
		{two, false, false, true},
		{[]string{"alias/ci"}, false, true, false},
		{fiveARNs(), false, true, false},
		{[]string{testKMSARN, testKMSARN}, false, false, false},
	} {
		if err := checkKMSWays(c.ids, c.recovery, c.single); (err == nil) != c.ok {
			t.Errorf("checkKMSWays(%v, %v, %v) = %v", c.ids, c.recovery, c.single, err)
		}
	}
}

// generate refuses every bad combination before it asks the server or AWS
// anything.
func TestGenerateKMSFlagChecks(t *testing.T) {
	testutil.SetHome(t, t.TempDir())
	isolateAWS(t)
	for args, want := range map[string]string{
		"--kms-arn " + testKMSARN + " --security-key --single":           "never both",
		"--kms-arn " + testKMSARN + " --password --single":               "replaces the password",
		"--kms-arn " + testKMSARN + " --backup":                          "repeat --kms-arn",
		"--kms-arn " + testKMSARN:                                        "second way in",
		"--kms-arn alias/deepsecret --single":                            "not a KMS key ARN",
		"--kms-arn 1234abcd-12ab-34cd-56ef-1234567890ab --single":        "not a KMS key ARN",
		"--kms-arn arn:aws:kms:eu-west-1:111122223333:alias/ci --single": "not a KMS key ARN",
		"--kms-arn " + testKMSARN + " --kms-arn " + testKMSARN:           "given twice",
		"--single": "go with --security-key or --kms-arn",
		"--kms-arn " + testKMSARN + " --single --label \u202ehidden": "--label",
	} {
		err := runRoot(append([]string{"identity", "generate"}, strings.Fields(args)...)...)
		if err == nil || !strings.Contains(err.Error()+errsDetail(err), want) {
			t.Errorf("generate %s: %v, want %q", args, err, want)
		}
	}
	names, _ := identity.List()
	if len(names) != 0 {
		t.Errorf("%d key pairs written", len(names))
	}
}

func TestImportCommand(t *testing.T) {
	testutil.SetHome(t, t.TempDir())
	src := t.TempDir()
	// A KMS key file made "elsewhere": in its own keys directory.
	_, fp := kmsKeyPair(t)
	data, _ := os.ReadFile(filepath.Join(config.KeysDir(), fp+".json"))
	if err := os.Remove(filepath.Join(config.KeysDir(), fp+".json")); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(src, "key.json")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runRoot("identity", "import", "--file", file); err != nil {
		t.Fatal(err)
	}
	testutil.AssertPrivate(t, filepath.Join(config.KeysDir(), fp+".json"))
	if identity.Protection(fp) != keystore.ProtectionKMS {
		t.Error("the imported key pair does not read")
	}
	if err := runRoot("identity", "import", "--file", file); err != nil {
		t.Errorf("same file again: %v", err)
	}
	other := append([]byte(" "), data...)
	if err := os.WriteFile(file, other, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runRoot("identity", "import", "--file", file); err == nil || !strings.Contains(errsDetail(err), "--replace") {
		t.Errorf("different file: %v", err)
	}
	if err := runRoot("identity", "import", "--file", file, "--replace"); err != nil {
		t.Errorf("--replace: %v", err)
	}
	// An unprotected key file is never imported.
	kp, _ := keys.Generate()
	plain, _ := keys.Fingerprint(kp)
	if err := keystore.Save(src, plain, kp, ""); err != nil {
		t.Fatal(err)
	}
	if err := runRoot("identity", "import", "--file", filepath.Join(src, plain+".json")); err == nil || !strings.Contains(err.Error(), "cannot be imported") {
		t.Errorf("unprotected: %v", err)
	}
	if err := runRoot("identity", "import"); err == nil {
		t.Error("import with no source")
	}
}

// doctor says nothing about AWS without a KMS key pair, and with one it
// reports the missing credentials instead of unlocking anything.
func TestDoctorKMS(t *testing.T) {
	testutil.SetHome(t, t.TempDir())
	isolateAWS(t)
	if _, ok := checkKMS(context.Background()); ok {
		t.Error("doctor reports AWS KMS with no KMS key pair")
	}
	kmsKeyPair(t)
	c, ok := checkKMS(context.Background())
	if !ok || c.ok || c.name != "AWS KMS" || !strings.Contains(c.fix, "AWS credentials") {
		t.Errorf("doctor without AWS credentials: %+v", c)
	}
}

// errsDetail is the detail err carries for its Error block.
func errsDetail(err error) string { return errs.JoinDetail("", err) }

// fiveARNs is one KMS key more than a key file takes.
func fiveARNs() []string {
	var out []string
	for i := 1; i <= 5; i++ {
		out = append(out, fmt.Sprintf("arn:aws:kms:eu-west-1:111122223333:key/00000000-0000-4000-8000-00000000000%d", i))
	}
	return out
}

// Every command's Error block for a KMS failure says what to do, and for
// credentials, where they came from: rejected credentials point at the
// profile, a refused permission at the policies.
func TestKMSFailureDetail(t *testing.T) {
	isolateAWS(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	rejected := fmt.Errorf("KMS key %s: %w", testKMSARN, fmt.Errorf("%w (UnrecognizedClientException: The security token included in the request is invalid.)", keystore.ErrKMSCredentialsRejected))
	denied := fmt.Errorf("KMS key %s: %w", testKMSARN, fmt.Errorf("%w: AccessDeniedException: not authorized", keystore.ErrKMSAccessDenied))

	_, detail := describeFailure(context.Background(), rejected)
	if !strings.Contains(detail, "the default profile") || !strings.Contains(detail, "--aws-profile") || strings.Contains(detail, "key policy") {
		t.Errorf("rejected, default profile: %q", detail)
	}
	t.Setenv("AWS_PROFILE", "deploy")
	if _, detail = describeFailure(context.Background(), rejected); !strings.Contains(detail, "the profile deploy (AWS_PROFILE)") {
		t.Errorf("rejected, AWS_PROFILE: %q", detail)
	}
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "/var/run/secrets/token")
	if _, detail = describeFailure(context.Background(), rejected); !strings.Contains(detail, "AWS_WEB_IDENTITY_TOKEN_FILE") {
		t.Errorf("rejected, web identity over AWS_PROFILE: %q", detail)
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
	if _, detail = describeFailure(context.Background(), rejected); !strings.Contains(detail, "AWS_WEB_IDENTITY_TOKEN_FILE") {
		t.Errorf("rejected, an access key id alone is not used: %q", detail)
	}
	t.Setenv("AWS_SECRET_ACCESS_KEY", "example")
	if _, detail = describeFailure(context.Background(), rejected); !strings.Contains(detail, "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY") {
		t.Errorf("rejected, environment keys: %q", detail)
	}
	identity.AWSProfile = "ci"
	t.Cleanup(func() { identity.AWSProfile = "" })
	if _, detail = describeFailure(context.Background(), rejected); !strings.Contains(detail, "the profile ci (--aws-profile)") {
		t.Errorf("rejected, --aws-profile: %q", detail)
	}
	if _, detail = describeFailure(context.Background(), denied); !strings.Contains(detail, "key policy") || strings.Contains(detail, "rejected") {
		t.Errorf("denied: %q", detail)
	}
	if _, detail = describeFailure(context.Background(), keystore.ErrKMSNotKeyARN); detail != "" {
		t.Errorf("not a key ARN gets a second hint: %q", detail)
	}
	if _, detail = describeFailure(context.Background(), fmt.Errorf("unrelated")); detail != "" {
		t.Errorf("unrelated error: %q", detail)
	}
}
