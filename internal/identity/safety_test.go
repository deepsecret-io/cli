// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package identity

import (
	"strings"
	"testing"

	"github.com/deepsecret-io/sdk"
)

// The fingerprints of the SDK's safety number vectors, and their numbers.
var (
	zeroFP = strings.Repeat("0", 64)
	ffFP   = strings.Repeat("f", 64)
	// The pair of zeroFP and ffFP in three rows of four groups.
	zeroFFRows = []string{"16409 37532 34229 26549", "62996 69170 22498 68061", "77197 31533 19831 84070"}
)

// Your half of a safety number is the primary key only when a key pair
// on this device is that key: the server's listing alone is not enough.
func TestPrimaryOnDevice(t *testing.T) {
	primary := []sdk.RemoteKey{{Fingerprint: ffFP}, {Fingerprint: strings.ToUpper(zeroFP), IsPrimary: true}}
	if got, err := PrimaryOnDevice(primary, []string{ffFP, zeroFP}); err != nil || got != zeroFP {
		t.Errorf("primary on this device: %q, %v", got, err)
	}
	if _, err := PrimaryOnDevice(primary, []string{ffFP}); err == nil || !strings.Contains(err.Error(), "not on this device") {
		t.Errorf("primary elsewhere: %v", err)
	}
	if _, err := PrimaryOnDevice([]sdk.RemoteKey{{Fingerprint: zeroFP}}, []string{zeroFP}); err == nil || !strings.Contains(err.Error(), "no primary key") {
		t.Errorf("no primary key: %v", err)
	}
	// A prefix the server lists does not pass for the key.
	if _, err := PrimaryOnDevice([]sdk.RemoteKey{{Fingerprint: zeroFP[:32], IsPrimary: true}}, []string{zeroFP}); err == nil {
		t.Error("a prefix passed for the primary key")
	}
}

// A key of yours shows its 30 digits on one line; a pair, 60 digits in
// three rows of four groups, the same whichever key is yours.
func TestSafetyNumberLayout(t *testing.T) {
	if got, err := SafetyNumber(zeroFP); err != nil || got != "22498 68061 77197 31533 19831 84070" {
		t.Errorf("own key: %q, %v", got, err)
	}
	for _, pair := range [][2]string{{zeroFP, ffFP}, {ffFP, zeroFP}} {
		rows, err := PairSafetyRows(pair[0], pair[1])
		if err != nil || strings.Join(rows, "|") != strings.Join(zeroFFRows, "|") {
			t.Errorf("pair %s/%s: %q, %v", pair[0][:4], pair[1][:4], rows, err)
		}
	}
	if _, err := PairSafetyRows(zeroFP, ffFP[:16]); err == nil {
		t.Error("a prefix got a safety number")
	}
}
