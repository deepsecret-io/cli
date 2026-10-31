// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/deepsecret-io/sdk"
	"github.com/deepsecret-io/sdk/crypto"
)

// ── Known keys ──────────────────────────────────────────────────────────────
//
// The SDK remembers the key it first used for each person and refuses a
// send to them, or a secret from them, under any other key. Accepting a
// new key replaces the old ones: sends go to it alone, and the old ones
// only check secrets they signed. Your own accounts are remembered too:
// only key pairs on this device pass for them. These commands show those
// keys, compare them with their owners, accept a changed one and forget
// them.

func newIdentityKnownCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "known [email]",
		Short: "List the keys this device accepted for other people",
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.MaximumNArgs(1)(cmd, args); err != nil {
				return err
			}
			if len(args) == 1 {
				return checkEmailArg(args[0])
			}
			return nil
		},
		RunE: func(_ *cobra.Command, args []string) error {
			c, err := newAuthenticatedClient()
			if err != nil {
				return err
			}
			email := ""
			if len(args) == 1 {
				email = args[0]
			}
			keys, err := c.KnownKeys(email)
			if err != nil {
				return err
			}
			if len(keys) == 0 {
				printDim("No known keys yet. The first secret to or from someone accepts their key.")
				return nil
			}
			printHeader(fmt.Sprintf("Known keys (%d)", len(keys)))
			fmt.Println()
			for _, k := range keys {
				state := keyStateLabel(k.State)
				if k.Replaced {
					state += ", replaced"
				}
				fmt.Printf("  %-32s  %s  %-20s  %s\n", safe(k.Email), crypto.ShortFingerprint(k.Fingerprint),
					state, k.FirstSeen.Local().Format("2006-01-02"))
			}
			fmt.Println()
			return nil
		},
	}
}

func newIdentityVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify <email> [fingerprint]",
		Short: "Compare someone's key with them, and mark it verified",
		Long: `Without a fingerprint, show the key the server lists for <email> in full,
and the keys this device accepted for them. Compare it with them over a
channel you trust; they see theirs with: secret identity show.

With the full fingerprint you compared, mark that key verified, accepting it
if this device did not know it.`,
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.RangeArgs(1, 2)(cmd, args); err != nil {
				return err
			}
			if err := checkEmailArg(args[0]); err != nil {
				return err
			}
			if len(args) == 2 {
				return checkFullFingerprintArg(args, 1)
			}
			return nil
		},
		RunE: func(_ *cobra.Command, args []string) error {
			c, err := newAuthenticatedClient()
			if err != nil {
				return err
			}
			email := args[0]
			if len(args) == 2 {
				if err := c.VerifyKey(email, args[1]); err != nil {
					return err
				}
				logInfo("ds.identity_verify", fmt.Sprintf("verified key %s of %s", args[1], safe(email)))
				printSuccess(fmt.Sprintf("Key %s of %s is verified", crypto.ShortFingerprint(args[1]), email))
				return nil
			}

			current, err := c.GetRecipientKeys(email)
			if err != nil {
				return err
			}
			known, err := c.KnownKeys(email)
			if err != nil {
				return err
			}
			printHeader("Key of " + email)
			fmt.Println()
			printKeyValues("Server lists", groupFingerprint(current.Fingerprint))
			printKeyValue("This device", knownKeyStatus(current.Fingerprint, known))
			fmt.Println()
			printDim(fmt.Sprintf("Compare it with %s over a channel you trust (they see theirs with: secret identity show).", email))
			printDim("If it matches, run:")
			printDim(fmt.Sprintf("  secret identity verify %s %s", email, current.Fingerprint))
			fmt.Println()
			return nil
		},
	}
}

func newIdentityAcceptCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "accept <email> <fingerprint>",
		Short: "Accept someone's new key, after confirming it with them",
		Long: `Accept <fingerprint> as <email>'s key on this device, after a send or
decrypt was refused because their key changed. Confirm the new key with
them over a channel you trust first. The full 64-character fingerprint is
required, and it must be a key the server lists for them.

It replaces their other keys: sends go to it alone, and the others only
check secrets they signed.`,
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.ExactArgs(2)(cmd, args); err != nil {
				return err
			}
			if err := checkEmailArg(args[0]); err != nil {
				return err
			}
			return checkFullFingerprintArg(args, 1)
		},
		RunE: func(_ *cobra.Command, args []string) error {
			c, err := newAuthenticatedClient()
			if err != nil {
				return err
			}
			if err := c.AcceptKey(args[0], args[1]); err != nil {
				return err
			}
			logInfo("ds.identity_accept", fmt.Sprintf("accepted key %s of %s", args[1], safe(args[0])))
			printSuccess(fmt.Sprintf("Accepted key %s for %s", crypto.ShortFingerprint(args[1]), args[0]))
			return nil
		},
	}
}

func newIdentityForgetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "forget <email> [fingerprint]",
		Short: "Forget the keys this device accepted for someone",
		Long: `Forget <fingerprint>, or every key this device accepted for <email>. Once
none is left, the next secret to or from them accepts their key on first
use again. For one of your own accounts, it forgets that it is yours.`,
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.RangeArgs(1, 2)(cmd, args); err != nil {
				return err
			}
			if err := checkEmailArg(args[0]); err != nil {
				return err
			}
			if len(args) == 2 {
				return checkFullFingerprintArg(args, 1)
			}
			return nil
		},
		RunE: func(_ *cobra.Command, args []string) error {
			c, err := newAuthenticatedClient()
			if err != nil {
				return err
			}
			fp := ""
			if len(args) == 2 {
				fp = args[1]
			}
			n, err := c.ForgetKey(args[0], fp)
			if err != nil {
				return err
			}
			if n == 0 {
				printDim(fmt.Sprintf("No known key to forget for %s", args[0]))
				return nil
			}
			logInfo("ds.identity_forget", fmt.Sprintf("forgot %d key(s) of %s", n, safe(args[0])))
			printSuccess(fmt.Sprintf("Forgot %d key%s of %s", n, pluralS(n), args[0]))
			return nil
		},
	}
}

// checkEmailArg checks an email given as an argument.
func checkEmailArg(email string) error {
	return sdk.ValidateRecipients([]string{email})
}

// checkFullFingerprintArg checks args[i], a full fingerprint, and leaves it
// in lower case. A prefix is refused: accepting or verifying a key names
// exactly one.
func checkFullFingerprintArg(args []string, i int) error {
	fp, err := checkFingerprint(args[i])
	if err != nil || len(fp) != crypto.FingerprintLen {
		return fmt.Errorf("invalid fingerprint %q: give the full 64-character fingerprint", args[i])
	}
	args[i] = fp
	return nil
}

// groupFingerprint splits a fingerprint into two lines of eight groups of
// four, for reading it aloud and comparing it.
func groupFingerprint(fp string) []string {
	var groups []string
	for i := 0; i < len(fp); i += 4 {
		groups = append(groups, safe(fp[i:min(i+4, len(fp))]))
	}
	half := (len(groups) + 1) / 2
	return []string{strings.Join(groups[:half], " "), strings.Join(groups[half:], " ")}
}

func keyStateLabel(s sdk.KeyState) string {
	switch s {
	case sdk.KeyFirstUse:
		return "first use"
	case sdk.KeyAccepted:
		return "accepted"
	case sdk.KeyVerified:
		return "verified"
	case sdk.KeyOwn:
		return "yours"
	}
	return safe(string(s))
}

// knownKeyStatus says what this device knows of fp, the key the server
// lists for someone whose accepted keys are known.
func knownKeyStatus(fp string, known []sdk.KnownKey) string {
	if len(known) == 0 {
		return "not known yet: the first secret to or from them accepts it"
	}
	var current, all []string
	for _, k := range known {
		all = append(all, crypto.ShortFingerprint(k.Fingerprint))
		if !k.Replaced {
			current = append(current, crypto.ShortFingerprint(k.Fingerprint))
		}
	}
	if len(current) == 0 {
		current = all
	}
	for _, k := range known {
		if k.Fingerprint != fp {
			continue
		}
		if k.Replaced {
			return ansiYellow + "replaced" + ansiReset + " by " + strings.Join(current, ", ")
		}
		return keyStateLabel(k.State) + ", since " + k.FirstSeen.Local().Format("2006-01-02")
	}
	return ansiYellow + "changed" + ansiReset + " from " + strings.Join(current, ", ")
}

// printFirstUse notes keys accepted on first use: nothing yet shows they
// are their owners', so they are worth comparing.
func printFirstUse(people []sdk.Recipient) {
	for _, p := range people {
		printDim(fmt.Sprintf("First secret with %s on this device: their key %s is now the one expected. Compare it with them: secret identity verify %s",
			p.Email, crypto.ShortFingerprint(p.Fingerprint), p.Email))
	}
}

// printKeyChangedHint follows a send or decrypt refused because someone's
// key changed with how to check and accept the new key.
func printKeyChangedHint(err error) {
	var changed *sdk.KeyChangedError
	if !errors.As(err, &changed) {
		return
	}
	label := "New key"
	if changed.Replaced {
		label = "Replaced key"
	}
	fmt.Fprintln(os.Stderr)
	printDim(fmt.Sprintf("Ask %s for their key fingerprint over a channel you trust, and compare it with:", changed.Email))
	printKeyValues(label, groupFingerprint(changed.Got))
	printDim("If it matches, accept it and try again:")
	printDim(fmt.Sprintf("  secret identity accept %s %s", changed.Email, changed.Got))
	fmt.Fprintln(os.Stderr)
}
