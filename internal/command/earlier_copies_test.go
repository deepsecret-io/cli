// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/deepsecret-io/deepsecret-go/keystore"
)

// stderrOf returns what fn writes to stderr.
func stderrOf(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	read := make(chan []byte)
	go func() {
		b, _ := io.ReadAll(r)
		read <- b
	}()
	saved := os.Stderr
	os.Stderr = w
	func() {
		defer func() { os.Stderr = saved }()
		fn()
	}()
	w.Close()
	return string(<-read)
}

// A key pair protected after it was stored with no protection has had its
// private keys in clear in every earlier copy: both protect commands warn
// and name the command for a new key pair. One that had a password is told
// that the password still opens earlier copies, with no warning.
func TestEarlierCopiesNote(t *testing.T) {
	for _, regenerate := range []string{
		"secret identity generate --security-key --recovery-code",
		"secret identity generate --kms-arn <KMS key ARN> --single",
	} {
		out := stderrOf(t, func() { earlierCopies(keystore.ProtectionNone, regenerate) })
		for _, want := range []string{
			"Warning:",
			"Copies of the key file made before now are still unprotected",
			"protecting it now does not undo that",
			"generate a new key pair instead: " + regenerate,
		} {
			if !strings.Contains(out, want) {
				t.Errorf("no protection before: the note lacks %q:\n%s", want, out)
			}
		}

		out = stderrOf(t, func() { earlierCopies(keystore.ProtectionPassword, regenerate) })
		if !strings.Contains(out, "still open with the password alone") {
			t.Errorf("password before: the note does not say the password opens earlier copies:\n%s", out)
		}
		if strings.Contains(out, "Warning:") || strings.Contains(out, regenerate) {
			t.Errorf("password before: the note warns or asks for a new key pair:\n%s", out)
		}
	}
}
