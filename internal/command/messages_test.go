// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/deepsecret-io/deepsecret-go/apierror"
	sdkidentity "github.com/deepsecret-io/deepsecret-go/identity"
	"github.com/deepsecret-io/deepsecret-go/secrets"
	"github.com/deepsecret-io/deepsecret-go/trust"

	"github.com/deepsecret-io/cli/internal/auth"
	"github.com/deepsecret-io/cli/internal/config"
	"github.com/deepsecret-io/cli/internal/errs"
	"github.com/deepsecret-io/cli/internal/testutil"
)

// An interrupted command says so, and keeps what its error says to do
// next, such as the command that finishes the upload. A timeout without
// Ctrl+C is not an interrupt: it is reported as the error it is.
func TestReportError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	interrupted := errs.WithDetail(&secrets.UploadInterruptedError{Err: context.Canceled}, resumeDetail("7da383f1-0000-4000-8000-000000000001"))
	var code int
	out := testutil.StderrOf(t, func() { code = reportError(ctx, interrupted) })
	if code != 130 || !strings.Contains(out, "Error: Interrupted") || !strings.Contains(out, "secret resume 7da383f1") {
		t.Fatalf("an interrupted upload: exit %d, %q", code, out)
	}

	out = testutil.StderrOf(t, func() {
		code = reportError(context.Background(), fmt.Errorf("could not reach the DeepSecret API: %w", context.DeadlineExceeded))
	})
	if code != 1 || strings.Contains(out, "Interrupted") || !strings.Contains(out, "Error: Could not reach the DeepSecret API") {
		t.Fatalf("a timeout: exit %d, %q", code, out)
	}
}

// A request the server refuses with 401 names the credential it refused
// and what to do about it, never the key itself, instead of the server's
// "Authentication required". Before a client is made, a 401 is reported
// as the error it is.
func TestReportRefusedCredential(t *testing.T) {
	saved := auth.Source
	t.Cleanup(func() { auth.Source = saved })
	refused := fmt.Errorf("could not fetch secret 01b5c5d0: %w", &apierror.Error{StatusCode: 401, Message: "Authentication required"})

	for source, want := range map[string][]string{
		"DS_API_KEY":     {"Error: The server refused the API key in DS_API_KEY", "Unset DS_API_KEY", "/account/api-keys"},
		"--api-key-file": {"Error: The server refused the API key from --api-key-file", "Leave out --api-key-file"},
		"saved API key":  {"Error: The server refused your saved API key", "secret login", "secret config --save-api-key --api-key-stdin"},
		"login session":  {"Error: Your login session has ended", "secret login"},
	} {
		auth.Source = source
		var code int
		out := testutil.StderrOf(t, func() { code = reportError(context.Background(), refused) })
		if code != 1 || strings.Contains(out, "Authentication required") || strings.Contains(out, "status 401") {
			t.Errorf("%s: exit %d, %q", source, code, out)
		}
		for _, w := range want {
			if !strings.Contains(out, w) {
				t.Errorf("%s: %q does not contain %q", source, out, w)
			}
		}
	}

	auth.Source = "DS_API_KEY"
	interrupted := errs.WithDetail(&secrets.UploadInterruptedError{Err: &apierror.Error{StatusCode: 401}}, resumeDetail("7da383f1-0000-4000-8000-000000000001"))
	if out := testutil.StderrOf(t, func() { reportError(context.Background(), interrupted) }); !strings.Contains(out, "refused the API key") || !strings.Contains(out, "secret resume 7da383f1") {
		t.Errorf("a refused upload drops how to resume it: %q", out)
	}

	auth.Source = ""
	if out := testutil.StderrOf(t, func() { reportError(context.Background(), refused) }); !strings.Contains(out, "Authentication required") {
		t.Errorf("no credential yet: %q", out)
	}
}

// A request refused with 402 shows the server's message, which says what
// to do (renew, ask the owner, choose a plan), as the whole summary: not
// the API's status, the SDK's steps, or a guess such as "not shared with
// you".
func TestReportPaymentRequired(t *testing.T) {
	saved := auth.Source
	t.Cleanup(func() { auth.Source = saved })
	auth.Source = "login session"
	const renew = "Your free trial or subscription has ended. Renew it in Billing at https://app.deepsecret.io/billing."
	expired := &apierror.Error{StatusCode: 402, Message: renew}

	for name, err := range map[string]error{
		"decrypt":      secretError(expired, "01b5c5d0-3374-4cf9-9360-b0af2e1e61d9"),
		"a send":       fmt.Errorf("resolve recipient you@example.com: lookup recipient: %w", expired),
		"an interrupt": errs.WithDetail(&secrets.UploadInterruptedError{Err: expired}, resumeDetail("7da383f1-0000-4000-8000-000000000001")),
	} {
		var code int
		out := testutil.StderrOf(t, func() { code = reportError(context.Background(), err) })
		if code != 1 || !strings.Contains(out, "Error: "+renew) {
			t.Errorf("%s: exit %d, %q", name, code, out)
		}
		for _, leak := range []string{"status 402", "lookup recipient", "not shared with you", "could not fetch"} {
			if strings.Contains(out, leak) {
				t.Errorf("%s: %q contains %q", name, out, leak)
			}
		}
	}
	if out := testutil.StderrOf(t, func() {
		reportError(context.Background(), errs.WithDetail(&secrets.UploadInterruptedError{Err: expired}, resumeDetail("7da383f1-0000-4000-8000-000000000001")))
	}); !strings.Contains(out, "secret resume 7da383f1") {
		t.Errorf("a refused upload drops how to resume it: %q", out)
	}
}

// A secret sealed before its name was signed says it was made by an earlier
// version and must be sent again, not "parse manifest: malformed manifest".
func TestReportOutdatedSecret(t *testing.T) {
	outdated := secretError(fmt.Errorf("parse manifest: %w", secrets.ErrOutdatedManifest), "01b5c5d0-3374-4cf9-9360-b0af2e1e61d9")
	var code int
	out := testutil.StderrOf(t, func() { code = reportError(context.Background(), outdated) })
	if code != 1 || !strings.Contains(out, "Error: This secret was made by an earlier version of DeepSecret") || !strings.Contains(out, "send it again") {
		t.Fatalf("exit %d, %q", code, out)
	}
	for _, leak := range []string{"manifest", "could not fetch"} {
		if strings.Contains(out, leak) {
			t.Errorf("%q contains %q", out, leak)
		}
	}
}

// A send or decrypt refused because someone's key changed says, in its
// Error block, how to compare the new key and accept it. Without your
// primary key on this device, that is its fingerprint (safety_test.go
// covers the safety number).
func TestKeyChangedDetail(t *testing.T) {
	saved := ownSafetyKey
	t.Cleanup(func() { ownSafetyKey = saved })
	ownSafetyKey = func(context.Context) (string, error) { return "", errors.New("your primary key is not on this device") }
	err := fmt.Errorf("check recipients: %w", &trust.KeyChangedError{Email: "bob@example.com", Known: []string{strings.Repeat("f", 64)}, Got: fullFP})
	summary, detail := describeFailure(context.Background(), err)
	if summary == "" {
		t.Fatal("no summary")
	}
	for _, want := range []string{
		"Ask bob@example.com for their key fingerprint",
		"  0123 4567 89ab cdef 0123 4567 89ab cdef\n  0123 4567 89ab cdef 0123 4567 89ab cdef",
		"secret identity accept bob@example.com " + fullFP,
	} {
		if !strings.Contains(detail, want) {
			t.Errorf("the detail %q does not hold %q", detail, want)
		}
	}
	if _, detail := errs.Describe(errors.New("another failure")); detail != "" {
		t.Errorf("another error got the detail %q", detail)
	}
}

// whoami fails when the registered keys cannot be listed, instead of
// reporting none, and names the primary key or says why there is none.
func TestRegisteredKeysStep(t *testing.T) {
	var keyList []sdkidentity.Key
	failing := registeredKeysStep(func() ([]sdkidentity.Key, error) { return nil, errors.New("server error") }, &keyList)
	if _, err := failing.Action(); err == nil || !strings.Contains(err.Error(), "could not list your registered keys: server error") {
		t.Fatalf("a failed listing: %v", err)
	}
	listed := registeredKeysStep(func() ([]sdkidentity.Key, error) {
		return []sdkidentity.Key{{Fingerprint: fullFP, IsPrimary: true}}, nil
	}, &keyList)
	if detail, err := listed.Action(); err != nil || detail != "keys=1" || len(keyList) != 1 {
		t.Fatalf("a listing: %q, %v, %d keys", detail, err, len(keyList))
	}
	if got := primaryKeyLabel(keyList); got != fullFP {
		t.Errorf("primary: %q", got)
	}
	if got := primaryKeyLabel(nil); !strings.HasPrefix(got, "none registered") {
		t.Errorf("no keys: %q", got)
	}
	if got := primaryKeyLabel([]sdkidentity.Key{{Fingerprint: fullFP}}); !strings.HasPrefix(got, "none set") {
		t.Errorf("no primary: %q", got)
	}
}

// doctor needs one working credential: a missing API key is no failure
// when the login works. A key the server refuses says how to fix it; one
// it could not check is not called refused; an expired session is not
// sent to the server.
func TestAuthChecks(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	verified := func(string) error { return nil }
	session := &config.TokenFile{Token: "t", Email: "you@example.com", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)}

	got := authChecks(session, nil, verified, now)
	if len(got) != 1 || !got[0].ok || got[0].detail != "you@example.com (verified)" {
		t.Fatalf("logged in, no API key: %+v", got)
	}
	got = authChecks(nil, nil, verified, now)
	if len(got) != 1 || got[0].ok || got[0].fix != "secret login" {
		t.Fatalf("no credential: %+v", got)
	}

	key := []credential{{"API key (DS_API_KEY)", "k", "unset DS_API_KEY, or set it to a valid key"}}
	refused := func(string) error { return &apierror.Error{StatusCode: 401, Message: "invalid key"} }
	if got := authChecks(nil, key, refused, now); got[0].ok || got[0].detail != "rejected by the server" || got[0].fix == "" {
		t.Fatalf("a refused key: %+v", got)
	}
	unreachable := func(string) error { return errors.New("dial tcp: connection refused") }
	if got := authChecks(nil, key, unreachable, now); got[0].ok || !strings.HasPrefix(got[0].detail, "could not be checked") || got[0].fix != "" {
		t.Fatalf("an unchecked key: %+v", got)
	}

	expired := *session
	expired.ExpiresAt = now.Add(-time.Minute).Format(time.RFC3339)
	asked := false
	got = authChecks(&expired, nil, func(string) error { asked = true; return nil }, now)
	if asked || got[0].ok || !strings.Contains(got[0].detail, "expired") || got[0].fix != "secret login" {
		t.Fatalf("an expired session: asked %v, %+v", asked, got)
	}
}

// identity list says a key pair is local-only only when the server was
// asked; without it, it says nothing of registration.
func TestKeyTags(t *testing.T) {
	for _, c := range []struct {
		securityKey bool
		encrypted   bool
		registered  *sdkidentity.Key
		checked     bool
		want        string
	}{
		{false, true, nil, false, "encrypted"},
		{false, false, nil, false, ""},
		{false, false, nil, true, "local-only"},
		{false, true, &sdkidentity.Key{IsPrimary: true}, true, "encrypted,primary,registered"},
		{false, false, &sdkidentity.Key{}, true, "registered"},
		{true, false, nil, true, "security-key,local-only"},
		{true, false, &sdkidentity.Key{IsPrimary: true}, true, "security-key,primary,registered"},
	} {
		if got := strings.Join(keyTags(c.securityKey, c.encrypted, c.registered, c.checked), ","); got != c.want {
			t.Errorf("keyTags(%v, %v, %v, %v) = %q, want %q", c.securityKey, c.encrypted, c.registered, c.checked, got, c.want)
		}
	}
}

// A page past the last one is empty, so list can refuse it instead of
// showing a header like "(21-20 of 20)".
func TestPageBounds(t *testing.T) {
	for _, c := range []struct{ total, page, limit, start, end int }{
		{45, 1, 20, 0, 20},
		{45, 3, 20, 40, 45},
		{45, 4, 20, 45, 45},
		{0, 1, 20, 0, 0},
	} {
		if start, end := pageBounds(c.total, c.page, c.limit); start != c.start || end != c.end {
			t.Errorf("pageBounds(%d, %d, %d) = %d, %d; want %d, %d", c.total, c.page, c.limit, start, end, c.start, c.end)
		}
	}
}

// Without --identity, sync registers the only key pair not registered
// yet, matching the server's fingerprints however long, and says what to
// do when there is none or several.
func TestKeyToSync(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	if _, err := keyToSync("", nil); err == nil || !strings.Contains(err.Error(), "no key pair on this device") {
		t.Fatalf("no key pairs: %v", err)
	}
	if err := os.MkdirAll(config.KeysDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, fp := range []string{a, b} {
		if err := os.WriteFile(filepath.Join(config.KeysDir(), fp+".json"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, err := keyToSync("", nil)
	if summary, detail := errs.Describe(err); summary != "2 key pairs on this device are not registered" || !strings.Contains(detail, a) || !strings.Contains(detail, b) {
		t.Fatalf("two unregistered: %q, %q", summary, detail)
	}
	if name, err := keyToSync("", []sdkidentity.Key{{Fingerprint: a[:32]}}); err != nil || name != b {
		t.Fatalf("one unregistered: %q, %v", name, err)
	}
	if _, err := keyToSync("", []sdkidentity.Key{{Fingerprint: a}, {Fingerprint: b}}); err == nil || !strings.Contains(err.Error(), "already registered") {
		t.Fatalf("all registered: %v", err)
	}
	if name, err := keyToSync(b[:16], nil); err != nil || name != b {
		t.Fatalf("a prefix: %q, %v", name, err)
	}
	if _, err := keyToSync(strings.Repeat("c", 16), nil); err == nil || !strings.Contains(err.Error(), "no key pair cccccccccccccccc") {
		t.Fatalf("an unknown prefix: %v", err)
	}
}

// login --check says a saved API key is used only without a login, and
// which credential commands use.
func TestShowAuthStatus(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	savedKey := auth.FlagKey
	t.Cleanup(func() { auth.FlagKey = savedKey })
	auth.FlagKey = ""
	if err := config.SaveToken("token", "you@example.com", time.Now().Add(time.Hour).UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if err := config.Save(&config.Config{APIKey: "ds_test_key"}); err != nil {
		t.Fatal(err)
	}
	out := testutil.AnsiEscape.ReplaceAllString(testutil.StderrOf(t, func() { _ = showAuthStatus() }), "")
	for _, want := range []string{
		`Login\s+you@example\.com \(browser sign-in\)`,
		`Saved API key\s+set \(used when not logged in\)`,
		`In use\s+login session`,
	} {
		if !regexp.MustCompile(want).MatchString(out) {
			t.Errorf("%q does not match %s", out, want)
		}
	}
}

// secret config reports a config file it cannot read, instead of showing
// the API key as not set.
func TestConfigReportsAnUnreadableFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("DS_API_KEY", "")
	if err := os.MkdirAll(config.Dir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.Path(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runRoot("config"); err == nil || !strings.Contains(err.Error(), "could not read "+config.Path()) {
		t.Fatalf("%v", err)
	}
}

// A send's done line names the secret, and the revision when the send
// added one to a secret of the same name.
func TestSendDetail(t *testing.T) {
	id := "0724ba1f-c173-46ef-88e2-6ea3056d8fb4"
	if got := sendDetail(secrets.Secret{ID: id, RevisionNumber: 1}); got != "id=0724ba1f" {
		t.Errorf("first revision: %q", got)
	}
	if got := sendDetail(secrets.Secret{ID: id, RevisionNumber: 3}); got != "id=0724ba1f revision=3" {
		t.Errorf("third revision: %q", got)
	}
}

// Without a home directory a command fails with an ordinary error, so main
// sets the exit code and closes the log; help and completion need no home
// directory.
func TestMissingHome(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	err := runRoot("whoami")
	if err == nil {
		t.Fatal("whoami ran without a home directory")
	}
	if summary, _ := errs.Describe(err); summary != "Cannot find your home directory" {
		t.Fatalf("summary %q", summary)
	}
	for _, args := range [][]string{{"help"}, {"help", "encrypt"}, {"completion", "zsh"}} {
		if err := runRoot(args...); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
}
