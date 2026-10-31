// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/deepsecret-io/sdk/api"
	"github.com/deepsecret-io/sdk/crypto"
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
  - The keys registered on the server, and which of them this device holds

Examples:
  secret doctor
  secret doc`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDoctor()
		},
	}
}

type checkResult struct {
	name   string
	ok     bool
	detail string
	fix    string
}

func runDoctor() error {
	var checks []checkResult
	checks = append(checks, checkAPIURL())
	checks = append(checks, checkAuth()...)
	if hasAuth() {
		checks = append(checks, checkPlan())
	}
	checks = append(checks, checkLocalKeys()...)
	if hasAuth() && hasLocalKeys() {
		checks = append(checks, checkRemoteSync()...)
	}

	if failed := printChecks(checks); failed > 0 {
		return fmt.Errorf("%d of %d checks failed", failed, len(checks))
	}
	fmt.Fprintln(os.Stderr)
	printSuccess(fmt.Sprintf("All %d checks passed.", len(checks)))
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
		mark, color := ansiGreen+"✓"+ansiReset, ansiDim
		if !c.ok {
			mark, color = ansiBoldRed+"✗"+ansiReset, ansiRed
			failed++
		}
		fmt.Fprintf(os.Stderr, "  %s %-*s  %s%s%s\n", mark, width, c.name, color, safe(c.detail), ansiReset)
		if !c.ok && c.fix != "" {
			fmt.Fprintf(os.Stderr, "    %-*s  %sfix: %s%s\n", width, "", ansiDim, safe(c.fix), ansiReset)
		}
	}
	return failed
}

func checkAPIURL() checkResult {
	return checkResult{name: "API URL", ok: true, detail: apiBaseURL + " (compiled in)"}
}

// credential is an API key doctor checks: the check's name, the key, and
// how to fix it when the server refuses it.
type credential struct {
	name, key, fix string
}

func checkAuth() []checkResult {
	var session *TokenFile
	if tf, err := loadTokenFile(); err == nil && tf.Token != "" {
		session = tf
	}
	var keys []credential
	if apiKey != "" {
		fix := "give a valid key with " + keyOrigin
		if keyOrigin == "DS_API_KEY" {
			fix = "unset DS_API_KEY, or set it to a valid key"
		}
		keys = append(keys, credential{"API key (" + keyOrigin + ")", apiKey, fix})
	}
	if cfg, err := loadConfig(); err == nil && cfg.APIKey != "" && cfg.APIKey != apiKey {
		keys = append(keys, credential{"API key (saved)", cfg.APIKey, "secret config --save-api-key --api-key-stdin"})
	}
	return authChecks(session, keys, verifyCredential, time.Now())
}

// verifyCredential asks the server whose key is. A login token gets a
// client that saves the token it renews: a renewal revokes the stored one.
func verifyCredential(key string) error {
	var c *Client
	var err error
	if token, ok := strings.CutPrefix(key, "bearer:"); ok {
		c, err = newSessionClient(token)
	} else {
		c, err = NewClient(apiBaseURL, key)
	}
	if err != nil {
		return err
	}
	_, err = c.WhoAmI()
	return err
}

// authChecks checks the login session (nil when there is none) and the
// API keys, verify asking the server about each. One working credential
// is enough, so none is missing unless all are.
func authChecks(session *TokenFile, keys []credential, verify func(key string) error, now time.Time) []checkResult {
	var results []checkResult
	if session != nil {
		results = append(results, checkLogin(session, verify, now))
	}
	for _, k := range keys {
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
func checkLogin(tf *TokenFile, verify func(key string) error, now time.Time) checkResult {
	r := checkResult{name: "Login"}
	account := orDefault(tf.Email, "account not recorded")
	if tf.ExpiresAt != "" {
		// As loadToken does, an expiry that does not parse counts as
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
	if errors.Is(err, api.ErrUnauthorized) || errors.Is(err, api.ErrForbidden) {
		return "rejected by the server", true
	}
	return "could not be checked: " + apiCause(err).Error(), false
}

func checkLocalKeys() []checkResult {
	names, err := listKeyPairs()
	if err != nil {
		return []checkResult{{name: "Key pairs", detail: "could not list them: " + err.Error()}}
	}
	if len(names) == 0 {
		return []checkResult{{name: "Key pairs", detail: "none on this device", fix: "secret identity generate --sync"}}
	}

	var results []checkResult
	for _, n := range names {
		kp, fp, err := readPublicKeys(n)
		if err != nil {
			results = append(results, checkResult{name: "Key pair", detail: n + ".json: " + err.Error()})
			continue
		}
		detail := crypto.ShortFingerprint(fp)
		if kp.Encrypted {
			detail += " (encrypted)"
		}
		results = append(results, checkResult{name: "Key pair", ok: true, detail: detail})
	}
	return results
}

// checkRemoteSync checks the keys registered on the server against the key
// pairs on this device: the primary key must be here, since secrets are
// sent to it, and each key pair here should be registered. A registered
// key elsewhere is fine.
func checkRemoteSync() []checkResult {
	remote, err := fetchRegisteredKeys()
	if err != nil {
		return []checkResult{{name: "Registered keys", detail: err.Error()}}
	}
	if len(remote) == 0 {
		return []checkResult{{name: "Registered keys", detail: "none on the server", fix: "secret identity sync"}}
	}

	names, _ := listKeyPairs() // checkLocalKeys reported a failure to list them
	here := func(fp string) bool {
		for _, n := range names {
			if fingerprintMatch(n, fp) {
				return true
			}
		}
		return false
	}
	var results []checkResult
	for _, k := range remote {
		short := crypto.ShortFingerprint(k.Fingerprint)
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
		_, fp, err := readPublicKeys(n)
		if err != nil || registeredKey(remote, fp) != nil {
			continue
		}
		results = append(results, checkResult{name: "Key pair", detail: crypto.ShortFingerprint(fp) + " is not registered", fix: "secret identity sync -i " + fp})
	}
	return results
}

func checkPlan() checkResult {
	r := checkResult{name: "Plan"}
	c, err := newAuthenticatedClient()
	if err != nil {
		r.detail = "not checked: " + err.Error()
		return r
	}
	actor, err := c.WhoAmI()
	if err != nil {
		r.detail = "could not fetch your account: " + apiCause(err).Error()
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
	if apiKey != "" {
		return true
	}
	if _, err := loadToken(); err == nil {
		return true
	}
	if cfg, err := loadConfig(); err == nil && cfg.APIKey != "" {
		return true
	}
	return false
}

func hasLocalKeys() bool {
	names, _ := listKeyPairs()
	return len(names) > 0
}
