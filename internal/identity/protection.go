// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package identity

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/deepsecret-io/deepsecret-go/awskms"
	"github.com/deepsecret-io/deepsecret-go/fido2"
	sdkidentity "github.com/deepsecret-io/deepsecret-go/identity"
	"github.com/deepsecret-io/deepsecret-go/keys"
	"github.com/deepsecret-io/deepsecret-go/keystore"

	"github.com/deepsecret-io/cli/internal/config"
	"github.com/deepsecret-io/cli/internal/console"
	"github.com/deepsecret-io/cli/internal/errs"
	"github.com/deepsecret-io/cli/internal/prompt"
)

// terminalPrompter asks for a security key's PIN on the terminal and says
// when to touch it.
type terminalPrompter struct{}

func (terminalPrompter) PIN(ctx context.Context, device string, retries int, wrong bool) ([]byte, error) {
	ask := fmt.Sprintf("PIN for %s: ", console.Safe(device))
	if retries >= 0 && (wrong || retries <= 3) {
		ask = fmt.Sprintf("PIN for %s (%d attempts left): ", console.Safe(device), retries)
	}
	if wrong {
		// The touch asked for was never needed: the key checks the PIN
		// first.
		fmt.Fprintln(os.Stderr, "That PIN is wrong.")
	}
	pin, err := prompt.Password(ctx, ask)
	if err != nil {
		return nil, err
	}
	if pin == "" {
		return nil, keystore.ErrCancelled
	}
	return []byte(pin), nil
}

func (terminalPrompter) Touch(device, reason string) {
	fmt.Fprintf(os.Stderr, "Touch %s %s. Ctrl-C cancels.\n", console.Safe(device), console.Safe(reason))
}

func (terminalPrompter) TouchDone() {}

func (terminalPrompter) Insert(want string) {
	fmt.Fprintf(os.Stderr, "Plug in %s. Ctrl-C cancels.\n", console.Safe(want))
}

// SecurityKey is the security key support of this build.
func SecurityKey() keystore.Authenticator { return fido2.New(terminalPrompter{}) }

// AWSProfile is the AWS profile KMS calls use, from the global --aws-profile
// flag. Empty uses AWS_PROFILE and the AWS default credential chain.
var AWSProfile string

// AppVersion is this CLI's version, named in the AWS user agent that
// CloudTrail records for every KMS call.
var AppVersion string

// KMS returns an AWS KMS client for key pairs protected by AWS KMS. Every
// call names a full key ARN and goes to that key's own region.
func KMS(ctx context.Context) (*awskms.Client, error) {
	return awskms.New(ctx, awskms.Options{Profile: AWSProfile, AppID: appID()})
}

// appID is "deepsecret-cli/<version>", or "deepsecret-cli" when the version
// holds anything an AWS app id may not.
func appID() string {
	for _, r := range AppVersion {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_'
		if !ok {
			return "deepsecret-cli"
		}
	}
	if AppVersion == "" || len(AppVersion) > 30 {
		return "deepsecret-cli"
	}
	return "deepsecret-cli/" + AppVersion
}

// Protection reads how the key pair name is protected, or "" when its
// file cannot be read.
func Protection(name string) keystore.Protection {
	info, err := keystore.ReadInfo(config.KeysDir(), name)
	if err != nil {
		return ""
	}
	return info.Protection
}

// ProtectionName is "security key" or "AWS KMS" when the key pair with
// fingerprint fp is on this device and protected by one, else "". Only a
// full fingerprint names a key file here, never a prefix: fp may come from
// the server.
func ProtectionName(fp string) string {
	if len(fp) != 64 {
		return ""
	}
	switch Protection(fp) {
	case keystore.ProtectionSecurityKey:
		return "security key"
	case keystore.ProtectionKMS:
		return "AWS KMS"
	}
	return ""
}

// ProtectionNote is ProtectionName in parentheses after a space, or "".
func ProtectionNote(fp string) string {
	if n := ProtectionName(fp); n != "" {
		return " (" + n + ")"
	}
	return ""
}

// ProtectionTag is the tag of a protection in key lists: "security-key",
// "aws-kms", "encrypted", or "" for none.
func ProtectionTag(p keystore.Protection) string {
	switch p {
	case keystore.ProtectionSecurityKey:
		return "security-key"
	case keystore.ProtectionKMS:
		return "aws-kms"
	case keystore.ProtectionPassword:
		return "encrypted"
	}
	return ""
}

// RemoteLabel is how the registered key k is protected, for key lists:
// "security-key" or "aws-kms" from its key file when it is on this device,
// "security-key (reported)" from the label one of the user's devices set
// when it is not, else "". The server does not check the label.
func RemoteLabel(k sdkidentity.Key) string {
	if len(k.Fingerprint) == 64 {
		if p := Protection(k.Fingerprint); p != "" {
			switch p {
			case keystore.ProtectionSecurityKey:
				return "security-key"
			case keystore.ProtectionKMS:
				return "aws-kms"
			}
			return ""
		}
	}
	if k.SecurityKey {
		return "security-key (reported)"
	}
	return ""
}

// RequirePasswordTerminal refuses to ask for the password of the key pair
// name when no terminal can answer, with what automation should use instead.
func RequirePasswordTerminal(name string) error {
	t, err := prompt.OpenTerminal()
	if err != nil {
		return errs.WithDetail(fmt.Errorf("key pair %s is protected by a password, which needs a terminal", keys.ShortFingerprint(name)),
			"Run the command in a terminal. Automation needs a key pair of its own, protected by AWS KMS:\n  secret identity generate --kms-arn <KMS key ARN> --single")
	}
	return t.Close()
}

// RequireTerminal refuses to start a security key request nobody can
// answer: it needs a touch, and usually a PIN typed on the terminal.
func RequireTerminal(name string) error {
	t, err := prompt.OpenTerminal()
	if err != nil {
		what := errors.New("a security key needs a terminal")
		if name != "" {
			what = fmt.Errorf("key pair %s is protected by a security key, which needs a terminal", keys.ShortFingerprint(name))
		}
		return errs.WithDetail(what, "Run the command in a terminal. Automation needs a key pair of its own, protected by AWS KMS:\n  secret identity generate --kms-arn <KMS key ARN> --single")
	}
	return t.Close()
}
