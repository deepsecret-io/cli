// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package identity

import (
	"context"
	"errors"
	"fmt"
	"os"

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

// Protection reads how the key pair name is protected, or "" when its
// file cannot be read.
func Protection(name string) keystore.Protection {
	info, err := keystore.ReadInfo(config.KeysDir(), name)
	if err != nil {
		return ""
	}
	return info.Protection
}

// SecurityKeyNote is " (security key)" when the key pair with fingerprint
// fp is on this device and protected by a security key, else "". Only a
// full fingerprint names a key file here, never a prefix: fp may come from
// the server.
func SecurityKeyNote(fp string) string {
	if len(fp) == 64 && Protection(fp) == keystore.ProtectionSecurityKey {
		return " (security key)"
	}
	return ""
}

// RemoteLabel is how the registered key k is protected, for key lists:
// "security-key" from its key file when it is on this device,
// "security-key (reported)" from the label one of the user's devices set
// when it is not, else "". The server does not check the label.
func RemoteLabel(k sdkidentity.Key) string {
	if len(k.Fingerprint) == 64 {
		if p := Protection(k.Fingerprint); p != "" {
			if p == keystore.ProtectionSecurityKey {
				return "security-key"
			}
			return ""
		}
	}
	if k.SecurityKey {
		return "security-key (reported)"
	}
	return ""
}

// RequireTerminal refuses to start a security key request nobody can
// answer: it needs a touch, and usually a PIN typed on the terminal.
func RequireTerminal(name string) error {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		what := errors.New("a security key needs a terminal")
		if name != "" {
			what = fmt.Errorf("key pair %s is protected by a security key, which needs a terminal", keys.ShortFingerprint(name))
		}
		return errs.WithDetail(what, "Run the command in a terminal. Automation needs a key pair of its own, with a password or none.")
	}
	return tty.Close()
}
