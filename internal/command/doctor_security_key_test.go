// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/deepsecret-io/deepsecret-go/fido2"
	"github.com/deepsecret-io/deepsecret-go/keystore"
)

// doctor's fix for security keys fits the system: libfido2 from its
// package manager where it is missing, and on Windows, where the CLI has
// no security key support, the recovery code instead of a package that
// would not help.
func TestSecurityKeyFix(t *testing.T) {
	missing := fmt.Errorf("%w: libfido2 was not found; install it", keystore.ErrNoSecurityKeySupport)
	for _, c := range []struct {
		goos string
		err  error
		want string
	}{
		{"darwin", missing, "brew install libfido2"},
		{"linux", missing, "apt install libfido2-1"},
		{"darwin", keystore.ErrNoSecurityKeySupport, "built with security key support"},
		{"linux", keystore.ErrNoSecurityKeySupport, "built with security key support"},
		{"windows", keystore.ErrNoSecurityKeySupport, "--recovery-code"},
		{"windows", missing, "--recovery-code"},
	} {
		if got := securityKeyFix(c.goos, c.err); !strings.Contains(got, c.want) {
			t.Errorf("%s, %v: %q, want %q in it", c.goos, c.err, got, c.want)
		}
	}

	// This build's own failure on Windows, from the SDK's stub, which
	// touches no library or device.
	if runtime.GOOS == "windows" {
		_, err := fido2.Check()
		if got := securityKeyFix(runtime.GOOS, err); err == nil || !strings.Contains(got, "--recovery-code") || strings.Contains(got, "brew") {
			t.Errorf("on Windows: %v, %q", err, got)
		}
	}
}
