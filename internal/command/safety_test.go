// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/deepsecret-io/deepsecret-go/trust"

	"github.com/deepsecret-io/cli/internal/testutil"
)

// The fingerprints of the SDK's safety number vectors, and their numbers.
var (
	zeroFP = strings.Repeat("0", 64)
	ffFP   = strings.Repeat("f", 64)
	// The pair of zeroFP and ffFP in three rows of four groups.
	zeroFFRows = []string{"16409 37532 34229 26549", "62996 69170 22498 68061", "77197 31533 19831 84070"}
)

// stubOwnKey makes ownSafetyKey answer fp, or err, for one test.
func stubOwnKey(t *testing.T, fp string, err error) {
	t.Helper()
	saved := ownSafetyKey
	t.Cleanup(func() { ownSafetyKey = saved })
	ownSafetyKey = func(context.Context) (string, error) { return fp, err }
}

// With your primary key on this device, a refusal because someone's key
// changed shows the safety number with the new key, and its fingerprint
// under it.
func TestKeyChangedDetailSafetyNumber(t *testing.T) {
	stubOwnKey(t, zeroFP, nil)
	err := fmt.Errorf("check recipients: %w", &trust.KeyChangedError{Email: "bob@example.com", Known: []string{fullFP}, Got: ffFP})
	_, detail := describeFailure(context.Background(), err)
	for _, want := range []string{
		"Compare the safety number with bob@example.com",
		"  " + strings.Join(zeroFFRows, "\n  "),
		"bob@example.com sees it with: secret identity verify <your email>",
		"Key fingerprint:\n\n  ffff ffff ffff ffff ffff ffff ffff ffff\n  ffff ffff ffff ffff ffff ffff ffff ffff",
		"secret identity accept bob@example.com " + ffFP,
	} {
		if !strings.Contains(detail, want) {
			t.Errorf("the detail %q does not hold %q", detail, want)
		}
	}
}

// identity verify <email> leads with the safety number, the key
// fingerprint under it; without your primary key here, it says why and
// shows the fingerprint alone.
func TestPrintKeyCheck(t *testing.T) {
	seen := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	known := []trust.KnownKey{{Email: "bob@example.com", Fingerprint: ffFP, State: trust.FirstUse, FirstSeen: seen}}

	out := testutil.StderrOf(t, func() { printKeyCheck("bob@example.com", ffFP, known, zeroFP, nil) })
	for _, want := range append([]string{
		"Safety number with bob@example.com",
		"Key fingerprint ffff ffff ffff ffff ffff ffff ffff ffff",
		"This device     first use, since ",
		"Both of you should see the same number",
		"secret identity verify bob@example.com " + ffFP,
	}, zeroFFRows...) {
		if !strings.Contains(out, want) {
			t.Errorf("%q does not hold %q", out, want)
		}
	}

	out = testutil.StderrOf(t, func() {
		printKeyCheck("bob@example.com", ffFP, known, "", errors.New("your primary key is not on this device"))
	})
	for _, want := range []string{
		"Key of bob@example.com",
		"Key fingerprint ffff ffff",
		"No safety number: your primary key is not on this device.",
		"secret identity verify bob@example.com " + ffFP,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("without your key: %q does not hold %q", out, want)
		}
	}
	if strings.Contains(out, zeroFFRows[0]) || strings.Contains(out, "Safety number with") {
		t.Errorf("a safety number without your key: %q", out)
	}
}

// identity known <email> shows the safety number for each key sends go
// to, not for a replaced key or one of your own.
func TestPrintKnownSafetyNumbers(t *testing.T) {
	stubOwnKey(t, zeroFP, nil)
	keys := []trust.KnownKey{
		{Email: "bob@example.com", Fingerprint: fullFP, State: trust.Verified, Replaced: true},
		{Email: "bob@example.com", Fingerprint: ffFP, State: trust.Accepted},
	}
	out := testutil.StderrOf(t, func() { printKnownSafetyNumbers(context.Background(), "bob@example.com", keys) })
	if !strings.Contains(out, "Safety number with bob@example.com, key ffffffffffffffff:") || !strings.Contains(out, zeroFFRows[2]) {
		t.Errorf("the current key: %q", out)
	}
	if strings.Contains(out, fullFP[:16]) {
		t.Errorf("a replaced key got a number: %q", out)
	}

	own := []trust.KnownKey{{Email: "me@example.com", Fingerprint: zeroFP, State: trust.Own}}
	if out := testutil.StderrOf(t, func() { printKnownSafetyNumbers(context.Background(), "me@example.com", own) }); out != "" {
		t.Errorf("your own account: %q", out)
	}

	stubOwnKey(t, "", errors.New("your primary key is not on this device"))
	out = testutil.StderrOf(t, func() { printKnownSafetyNumbers(context.Background(), "bob@example.com", keys) })
	if !strings.Contains(out, "No safety number with bob@example.com: your primary key is not on this device") {
		t.Errorf("without your key: %q", out)
	}
}
