// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	deepsecret "github.com/deepsecret-io/deepsecret-go"
	"github.com/deepsecret-io/deepsecret-go/apierror"
	"github.com/deepsecret-io/deepsecret-go/fido2"
	"github.com/deepsecret-io/deepsecret-go/keys"
	"github.com/deepsecret-io/deepsecret-go/keystore"
	"github.com/spf13/cobra"

	"github.com/deepsecret-io/cli/internal/auth"
	"github.com/deepsecret-io/cli/internal/config"
	"github.com/deepsecret-io/cli/internal/console"
	"github.com/deepsecret-io/cli/internal/errs"
	"github.com/deepsecret-io/cli/internal/fingerprint"
	"github.com/deepsecret-io/cli/internal/identity"
	"github.com/deepsecret-io/cli/internal/ui"
)

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "doctor",
		Aliases: []string{"doc"},
		Args:    cobra.NoArgs,
		Short:   "Check CLI health and configuration (alias: doc)",
		Long: `Run diagnostic checks on your DeepSecret CLI setup, and fail when one
does.

Checks:
  - API URL configuration
  - Authentication: the login session and any API key, each verified with
    the server
  - Your plan
  - The key pairs on this device
  - Security key support (libfido2), when a key pair is protected by one
  - The keys registered on the server, and which of them this device holds

Examples:
  secret doctor
  secret doc`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDoctor(cmd.Context())
		},
	}
}

type checkResult struct {
	name   string
	ok     bool
	detail string
	fix    string
}

func runDoctor(ctx context.Context) error {
	var checks []checkResult
	checks = append(checks, checkAPIURL())
	checks = append(checks, checkAuth(ctx)...)
	if hasAuth() {
		checks = append(checks, checkPlan(ctx))
	}
	checks = append(checks, checkLocalKeys()...)
	if c, ok := checkSecurityKeys(); ok {
		checks = append(checks, c)
	}
	if hasAuth() && hasLocalKeys() {
		checks = append(checks, checkRemoteSync(ctx)...)
	}

	if failed := printChecks(checks); failed > 0 {
		return fmt.Errorf("%d of %d checks failed", failed, len(checks))
	}
	fmt.Fprintln(os.Stderr)
	ui.Success(fmt.Sprintf("All %d checks passed.", len(checks)))
	return nil
}

// printChecks prints each check on a line, a checklist: a mark, its name
// and what it found, and under a failed one how to fix it. It returns how
// many failed.
func printChecks(checks []checkResult) int {
	width := 0
	for _, c := range checks {
		width = max(width, len(c.name))
	}
	failed := 0
	for _, c := range checks {
		mark, color := console.Green+"✓"+console.Reset, console.Dim
		if !c.ok {
			mark, color = console.BoldRed+"✗"+console.Reset, console.Red
			failed++
		}
		fmt.Fprintf(os.Stderr, "  %s %-*s  %s%s%s\n", mark, width, c.name, color, console.Safe(c.detail), console.Reset)
		if !c.ok && c.fix != "" {
			fmt.Fprintf(os.Stderr, "    %-*s  %sfix: %s%s\n", width, "", console.Dim, console.Safe(c.fix), console.Reset)
		}
	}
	return failed
}

func checkAPIURL() checkResult {
	return checkResult{name: "API URL", ok: true, detail: config.APIBaseURL + " (compiled in)"}
}

// credential is an API key doctor checks: the check's name, the key, and
// how to fix it when the server refuses it.
type credential struct {
	name, key, fix string
}

func checkAuth(ctx context.Context) []checkResult {
	var session *config.TokenFile
	if tf, err := config.LoadTokenFile(); err == nil && tf.Token != "" {
		session = tf
	}
	var keyList []credential
	if auth.FlagKey != "" {
		fix := "give a valid key with " + auth.FlagKeyOrigin
		if auth.FlagKeyOrigin == "DS_API_KEY" {
			fix = "unset DS_API_KEY, or set it to a valid key"
		}
		keyList = append(keyList, credential{"API key (" + auth.FlagKeyOrigin + ")", auth.FlagKey, fix})
	}
	if cfg, err := config.Load(); err == nil && cfg.APIKey != "" && cfg.APIKey != auth.FlagKey {
		keyList = append(keyList, credential{"API key (saved)", cfg.APIKey, "secret config --save-api-key --api-key-stdin"})
	}
	verify := func(key string) error { return verifyCredential(ctx, key) }
	return authChecks(session, keyList, verify, time.Now())
}

// verifyCredential asks the server whose key is. A login token gets a
// client that saves the token it renews: a renewal revokes the stored one.
func verifyCredential(ctx context.Context, key string) error {
	var c *deepsecret.Client
	var err error
	if token, ok := strings.CutPrefix(key, "bearer:"); ok {
		c, err = auth.NewSessionClient(token)
	} else {
		c, err = auth.NewClient(config.APIBaseURL, key)
	}
	if err != nil {
		return err
	}
	_, err = c.Identity.WhoAmI(ctx)
	return err
}

// authChecks checks the login session (nil when there is none) and the
// API keys, verify asking the server about each. One working credential
// is enough, so none is missing unless all are.
func authChecks(session *config.TokenFile, keyList []credential, verify func(key string) error, now time.Time) []checkResult {
	var results []checkResult
	if session != nil {
		results = append(results, checkLogin(session, verify, now))
	}
	for _, k := range keyList {
		r := checkResult{name: k.name, ok: true, detail: "verified"}
		if err := verify(k.key); err != nil {
			var rejected bool
			r.ok = false
			if r.detail, rejected = verifyFailure(err); rejected {
				r.fix = k.fix
			}
		}
		results = append(results, r)
	}
	if len(results) == 0 {
		results = append(results, checkResult{name: "Login", detail: "not logged in, and no API key is set", fix: "secret login"})
	}
	return results
}

// checkLogin checks the stored login session tf.
func checkLogin(tf *config.TokenFile, verify func(key string) error, now time.Time) checkResult {
	r := checkResult{name: "Login"}
	account := orDefault(tf.Email, "account not recorded")
	if tf.ExpiresAt != "" {
		// As config.LoadToken does, an expiry that does not parse counts as
		// passed.
		if exp, err := time.Parse(time.RFC3339, tf.ExpiresAt); err != nil || !now.Before(exp) {
			r.detail, r.fix = account+": the session expired", "secret login"
			return r
		}
	}
	if err := verify("bearer:" + tf.Token); err != nil {
		var rejected bool
		if r.detail, rejected = verifyFailure(err); rejected {
			r.fix = "secret login"
		}
		r.detail = account + ": " + r.detail
		return r
	}
	r.ok, r.detail = true, account+" (verified)"
	return r
}

// verifyFailure says why a credential did not verify, and whether the
// server refused it, rather than not being reached.
func verifyFailure(err error) (detail string, rejected bool) {
	if errors.Is(err, apierror.ErrUnauthorized) || errors.Is(err, apierror.ErrForbidden) {
		return "rejected by the server", true
	}
	return "could not be checked: " + errs.APICause(err).Error(), false
}

func checkLocalKeys() []checkResult {
	names, err := identity.List()
	if err != nil {
		return []checkResult{{name: "Key pairs", detail: "could not list them: " + err.Error()}}
	}
	if len(names) == 0 {
		return []checkResult{{name: "Key pairs", detail: "none on this device", fix: "secret identity generate"}}
	}

	var results []checkResult
	for _, n := range names {
		_, fp, err := identity.ReadPublicKeys(n)
		if err != nil {
			results = append(results, checkResult{name: "Key pair", detail: n + ".json: " + err.Error()})
			continue
		}
		detail := keys.ShortFingerprint(fp)
		if identity.Protection(n) == keystore.ProtectionPassword {
			detail += " (encrypted)"
		}
		if identity.Protection(n) == keystore.ProtectionSecurityKey {
			detail += " (security key)"
		}
		results = append(results, checkResult{name: "Key pair", ok: true, detail: detail})
	}
	return results
}

// checkSecurityKeys checks that a key pair protected by a security key can
// be unlocked here: libfido2 is installed, and a FIDO2 device is
// connected. It is reported only when such a key pair exists, so a user
// without a security key sees nothing about them.
func checkSecurityKeys() (checkResult, bool) {
	names, _ := identity.List()
	protected := 0
	for _, n := range names {
		if identity.Protection(n) == keystore.ProtectionSecurityKey {
			protected++
		}
	}
	if protected == 0 {
		return checkResult{}, false
	}
	st, err := fido2.Check()
	if err != nil {
		fix := "brew install libfido2"
		if runtime.GOOS == "linux" {
			fix = "apt install libfido2-1 (Debian, Ubuntu) or dnf install libfido2 (Fedora)"
		}
		if errors.Is(err, keystore.ErrNoSecurityKeySupport) && !strings.Contains(err.Error(), "libfido2") {
			fix = "use a release of the CLI built with security key support"
		}
		return checkResult{name: "Security keys", detail: err.Error(), fix: fix}, true
	}
	detail := "libfido2 at " + console.Safe(st.Library) + ", "
	switch len(st.Devices) {
	case 0:
		detail += "no security key connected"
		if runtime.GOOS == "linux" {
			detail += " (if one is plugged in, your user may lack access to it: check its udev rules)"
		}
	default:
		names := make([]string, len(st.Devices))
		for i, d := range st.Devices {
			names[i] = console.Safe(d)
		}
		detail += "connected: " + strings.Join(names, ", ")
	}
	return checkResult{name: "Security keys", ok: true, detail: detail}, true
}

// checkRemoteSync checks the keys registered on the server against the key
// pairs on this device: the primary key must be here, since secrets are
// sent to it, and each key pair here should be registered. A registered
// key elsewhere is fine.
func checkRemoteSync(ctx context.Context) []checkResult {
	remote, err := identity.FetchRegistered(ctx)
	if err != nil {
		return []checkResult{{name: "Registered keys", detail: err.Error()}}
	}
	if len(remote) == 0 {
		return []checkResult{{name: "Registered keys", detail: "none on the server", fix: "secret identity sync"}}
	}

	names, _ := identity.List() // checkLocalKeys reported a failure to list them
	here := func(fp string) bool {
		for _, n := range names {
			if fingerprint.Match(n, fp) {
				return true
			}
		}
		return false
	}
	var results []checkResult
	for _, k := range remote {
		short := keys.ShortFingerprint(k.Fingerprint)
		switch {
		case k.IsPrimary && here(k.Fingerprint):
			results = append(results, checkResult{name: "Primary key", ok: true, detail: short + " is on this device"})
		case k.IsPrimary:
			results = append(results, checkResult{name: "Primary key", detail: short + " is not on this device, so secrets sent to you cannot be decrypted here",
				fix: "decrypt on the device that holds it, or make a key pair here your primary key: secret identity set-primary <fingerprint>"})
		case here(k.Fingerprint):
			results = append(results, checkResult{name: "Registered key", ok: true, detail: short + " is on this device"})
		default:
			results = append(results, checkResult{name: "Registered key", ok: true, detail: short + " is not on this device"})
		}
	}
	for _, n := range names {
		_, fp, err := identity.ReadPublicKeys(n)
		if err != nil || identity.Registered(remote, fp) != nil {
			continue
		}
		results = append(results, checkResult{name: "Key pair", detail: keys.ShortFingerprint(fp) + " is not registered", fix: "secret identity sync -i " + fp})
	}
	return results
}

func checkPlan(ctx context.Context) checkResult {
	r := checkResult{name: "Plan"}
	c, err := auth.NewAuthenticatedClient()
	if err != nil {
		r.detail = "not checked: " + err.Error()
		return r
	}
	actor, err := c.Identity.WhoAmI(ctx)
	if err != nil {
		r.detail = "could not fetch your account: " + errs.APICause(err).Error()
		return r
	}
	if actor.TierName == "" {
		r.detail, r.fix = "no active plan", "choose one at https://app.deepsecret.io/tiers"
		return r
	}
	r.ok, r.detail = true, fmt.Sprintf("%s (%s)", actor.TierName, subscriptionStatus(actor.SubscriptionStatus, actor.Subscription.TrialEndsAt, time.Now()))
	return r
}

func hasAuth() bool {
	if auth.FlagKey != "" {
		return true
	}
	if _, err := config.LoadToken(); err == nil {
		return true
	}
	if cfg, err := config.Load(); err == nil && cfg.APIKey != "" {
		return true
	}
	return false
}

func hasLocalKeys() bool {
	names, _ := identity.List()
	return len(names) > 0
}
