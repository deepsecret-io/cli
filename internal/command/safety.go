// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"context"
	"fmt"
	"os"

	"github.com/deepsecret-io/deepsecret-go/keys"
	"github.com/deepsecret-io/deepsecret-go/trust"

	"github.com/deepsecret-io/cli/internal/console"
	"github.com/deepsecret-io/cli/internal/identity"
	"github.com/deepsecret-io/cli/internal/ui"
)

// ── Safety numbers ──────────────────────────────────────────────────────────
//
// A safety number is a key fingerprint as digits, for two people to read
// to each other (sdk/PROTOCOL_V4.md §11). With someone else it is the
// number of your primary key and their key: the same 60 digits on both
// sides. A key of yours alone has 30 digits. The hex fingerprint stays
// under it as "Key fingerprint", for scripts and older clients.

// ownSafetyKey is your half of a safety number with someone: the
// fingerprint of your primary key, or why there is none. It is a variable
// so tests answer without a server.
var ownSafetyKey = identity.LocalPrimaryKey

// printSafetyRows prints a safety number's rows as a block to read aloud.
func printSafetyRows(rows []string) {
	for _, r := range rows {
		fmt.Fprintf(os.Stderr, "    %s%s%s\n", console.Bold, r, console.Reset)
	}
}

// sameNumberHint says how the other person sees the same number.
func sameNumberHint(email string) string {
	return fmt.Sprintf("Both of you should see the same number. %s sees it with: secret identity verify <your email>", email)
}

// printKnownSafetyNumbers prints, under identity known <email>, the
// safety number with email for each of their keys sends go to, or why
// there is none.
func printKnownSafetyNumbers(ctx context.Context, email string, keyList []trust.KnownKey) {
	var current []trust.KnownKey
	for _, k := range keyList {
		if !k.Replaced && k.State != trust.Own {
			current = append(current, k)
		}
	}
	if len(current) == 0 {
		return
	}
	email = console.Safe(email)
	own, err := ownSafetyKey(ctx)
	if err != nil {
		ui.Dimmed(fmt.Sprintf("No safety number with %s: %v. Compare key fingerprints with: secret identity verify %s", email, err, email))
		fmt.Fprintln(os.Stderr)
		return
	}
	for _, k := range current {
		rows, err := identity.PairSafetyRows(own, k.Fingerprint)
		if err != nil {
			continue
		}
		ui.Dimmed(fmt.Sprintf("Safety number with %s, key %s:", email, console.Safe(keys.ShortFingerprint(k.Fingerprint))))
		printSafetyRows(rows)
		fmt.Fprintln(os.Stderr)
	}
	ui.Dimmed(sameNumberHint(email))
	fmt.Fprintln(os.Stderr)
}
