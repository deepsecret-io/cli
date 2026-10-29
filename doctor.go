// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/deepsecret-io/sdk/crypto"
)

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "doctor",
		Aliases: []string{"doc"},
		Args:    cobra.NoArgs,
		Short:   "Check CLI health and configuration (alias: doc)",
		Long: `Run diagnostic checks on your DeepSecret CLI setup.

Checks:
  - API URL configuration
  - Authentication (login token or API key)
  - Local identity keys
  - Remote key sync status
  - Key fingerprint matching

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
	dbg("doctor", "starting diagnostics")
	var checks []checkResult

	// 1. Config / API URL
	checks = append(checks, checkAPIURL())

	// 2. Authentication
	checks = append(checks, checkAuth()...)

	// 3. Active plan
	if hasAuth() {
		checks = append(checks, checkPlan())
	}

	// 4. Local identities
	localKeys := checkLocalKeys()
	checks = append(checks, localKeys...)

	// 5. Remote sync (only if authenticated and has local keys)
	if hasAuth() && hasLocalKeys() {
		checks = append(checks, checkRemoteSync()...)
	}

	// Compute max name width for alignment
	maxName := 0
	for _, c := range checks {
		if len(c.name) > maxName {
			maxName = len(c.name)
		}
	}

	// Print results
	pass := 0
	fail := 0
	for _, c := range checks {
		if c.ok {
			fmt.Fprintf(os.Stderr, "%sds.doctor:%s %s✓%s %-*s  %s%s%s\n",
				ansiCyan, ansiReset, ansiGreen, ansiReset, maxName, c.name, ansiDim, c.detail, ansiReset)
			pass++
		} else {
			fmt.Fprintf(os.Stderr, "%sds.doctor:%s %s✗%s %-*s  %s%s%s\n",
				ansiCyan, ansiReset, ansiBoldRed, ansiReset, maxName, c.name, ansiRed, c.detail, ansiReset)
			if c.fix != "" {
				fmt.Fprintf(os.Stderr, "%sds.doctor:%s   %sfix: %s%s\n",
					ansiCyan, ansiReset, ansiDim, c.fix, ansiReset)
			}
			fail++
		}
	}

	fmt.Fprintln(os.Stderr)
	summary := fmt.Sprintf("%d passed, %d failed", pass, fail)
	if fail == 0 {
		fmt.Fprintf(os.Stderr, "%sds.doctor:%s %s%s, all good%s\n", ansiCyan, ansiReset, ansiGreen, summary, ansiReset)
	} else {
		fmt.Fprintf(os.Stderr, "%sds.doctor:%s %s%s%s\n", ansiCyan, ansiReset, ansiRed, summary, ansiReset)
	}
	return nil
}

func checkAPIURL() checkResult {
	return checkResult{name: "API URL", ok: true, detail: apiBaseURL + " (compiled in)"}
}

func checkAuth() []checkResult {
	var results []checkResult
	apiBase := apiBaseURL

	// Check login token
	tf, err := loadTokenFile()
	if err == nil && tf.Token != "" {
		exp, _ := time.Parse(time.RFC3339, tf.ExpiresAt)
		if time.Now().After(exp) {
			results = append(results, checkResult{name: "Login token", ok: false, detail: "expired", fix: "secret login"})
		} else {
			remaining := time.Until(exp).Round(time.Minute)
			// Test token against API
			if apiBase != "" {
				tc, tcErr := NewClient(apiBase, "bearer:"+tf.Token)
				if tcErr != nil {
					results = append(results, checkResult{name: "Login token", ok: false, detail: fmt.Sprintf("%s: %v", tf.Email, tcErr), fix: "secret login"})
				} else if _, err := tc.WhoAmI(); err != nil {
					results = append(results, checkResult{name: "Login token", ok: false, detail: fmt.Sprintf("%s: rejected by the server", tf.Email), fix: "secret login"})
				} else {
					results = append(results, checkResult{name: "Login token", ok: true, detail: fmt.Sprintf("%s (%s remaining, verified)", tf.Email, remaining)})
				}
			} else {
				results = append(results, checkResult{name: "Login token", ok: true, detail: fmt.Sprintf("%s (%s remaining)", tf.Email, remaining)})
			}
		}
	} else {
		results = append(results, checkResult{name: "Login token", ok: false, detail: "not found", fix: "secret login"})
	}

	// Check the API key, reporting each source separately
	envKey := os.Getenv("DS_API_KEY")
	var cfgKey string
	if cfg, err := loadConfig(); err == nil {
		cfgKey = cfg.APIKey
	}

	if envKey != "" {
		if apiBase != "" {
			tc, tcErr := NewClient(apiBase, envKey)
			if tcErr != nil {
				results = append(results, checkResult{name: "API key (env)", ok: false, detail: tcErr.Error()})
			} else if _, err := tc.WhoAmI(); err != nil {
				results = append(results, checkResult{name: "API key (env)", ok: false, detail: "rejected by server", fix: "unset DS_API_KEY or update it"})
			} else {
				results = append(results, checkResult{name: "API key (env)", ok: true, detail: "set (verified)"})
			}
		} else {
			results = append(results, checkResult{name: "API key (env)", ok: true, detail: "set"})
		}
	}

	if cfgKey != "" && cfgKey != envKey {
		if apiBase != "" {
			tc, tcErr := NewClient(apiBase, cfgKey)
			if tcErr != nil {
				results = append(results, checkResult{name: "API key (config)", ok: false, detail: tcErr.Error()})
			} else if _, err := tc.WhoAmI(); err != nil {
				results = append(results, checkResult{name: "API key (config)", ok: false, detail: "rejected by server", fix: "secret config --save-api-key --api-key-stdin"})
			} else {
				results = append(results, checkResult{name: "API key (config)", ok: true, detail: "set (verified)"})
			}
		} else {
			results = append(results, checkResult{name: "API key (config)", ok: true, detail: "set"})
		}
	}

	if envKey == "" && cfgKey == "" {
		results = append(results, checkResult{name: "API key", ok: false, detail: "not set (optional if logged in)", fix: "secret config --save-api-key --api-key-stdin"})
	}

	return results
}

func checkLocalKeys() []checkResult {
	names, err := listKeyPairs()
	if err != nil {
		return []checkResult{{name: "Local identities", ok: false, detail: err.Error()}}
	}
	if len(names) == 0 {
		return []checkResult{{name: "Local identities", ok: false, detail: "none found", fix: "secret id gen"}}
	}

	var results []checkResult
	for _, n := range names {
		data, err := os.ReadFile(filepath.Join(keysDir(), n+".json")) // #nosec G304 -- n is a file name listKeyPairs read from the keys directory.
		if err != nil {
			results = append(results, checkResult{name: "Identity", ok: false, detail: safe(crypto.ShortFingerprint(n)) + " unreadable"})
			continue
		}
		var raw crypto.KeyPair
		if json.Unmarshal(data, &raw) != nil {
			results = append(results, checkResult{name: "Identity", ok: false, detail: safe(crypto.ShortFingerprint(n)) + " corrupt"})
			continue
		}
		fp, _ := crypto.Fingerprint(&raw)
		encrypted := ""
		if raw.Encrypted {
			encrypted = " (encrypted)"
		}
		results = append(results, checkResult{name: "Identity", ok: true, detail: crypto.ShortFingerprint(fp) + encrypted})
	}
	return results
}

func checkRemoteSync() []checkResult {
	c, err := newAuthenticatedClient()
	if err != nil {
		return nil
	}

	// Fetch remote keys (source of truth)
	remoteKeys, err := c.ListRemoteKeys()
	if err != nil {
		return []checkResult{{name: "Remote sync", ok: false, detail: "failed to fetch remote keys", fix: "check your authentication"}}
	}

	if len(remoteKeys) == 0 {
		return []checkResult{{name: "Remote sync", ok: false, detail: "no keys registered on server", fix: "secret id sync"}}
	}

	var results []checkResult

	// Check each server key has a local match (server is source of truth)
	for _, k := range remoteKeys {
		label := "Sync"
		if k.IsPrimary {
			label = "Primary key"
		}
		_, err := loadKeyPair(k.Fingerprint)
		if err != nil {
			results = append(results, checkResult{name: label, ok: false, detail: safe(crypto.ShortFingerprint(k.Fingerprint)) + " not found locally", fix: "key may have been generated on another machine"})
		} else {
			results = append(results, checkResult{name: label, ok: true, detail: safe(crypto.ShortFingerprint(k.Fingerprint)) + " synced"})
		}
	}

	// Check local keys not on server
	names, _ := listKeyPairs()
	remoteFPs := make(map[string]bool)
	for _, k := range remoteKeys {
		remoteFPs[k.Fingerprint] = true
	}
	for _, n := range names {
		data, err := os.ReadFile(filepath.Join(keysDir(), n+".json")) // #nosec G304 -- n is a file name listKeyPairs read from the keys directory.
		if err != nil {
			continue
		}
		var raw crypto.KeyPair
		if json.Unmarshal(data, &raw) != nil {
			continue
		}
		fp, _ := crypto.Fingerprint(&raw)
		if !remoteFPs[fp] {
			results = append(results, checkResult{name: "Local only", ok: false, detail: crypto.ShortFingerprint(fp) + " not on server", fix: fmt.Sprintf("secret identity sync -i %s", crypto.ShortFingerprint(fp))})
		}
	}

	return results
}

func checkPlan() checkResult {
	c, err := newAuthenticatedClient()
	if err != nil {
		return checkResult{name: "Active plan", ok: false, detail: "could not resolve config"}
	}
	actor, err := c.WhoAmI()
	if err != nil {
		return checkResult{name: "Active plan", ok: false, detail: "failed to fetch account info"}
	}
	if actor.TierName == "" {
		return checkResult{name: "Active plan", ok: false, detail: "no active plan", fix: "activate a plan at https://app.deepsecret.io/tiers"}
	}
	status := actor.SubscriptionStatus
	if status == "" || status == "inactive" {
		status = "free"
	}
	return checkResult{name: "Active plan", ok: true, detail: fmt.Sprintf("%s (%s)", actor.TierName, status)}
}

func hasAuth() bool {
	if _, err := loadToken(); err == nil {
		return true
	}
	if key := os.Getenv("DS_API_KEY"); key != "" {
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
