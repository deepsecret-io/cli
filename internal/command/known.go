// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/deepsecret-io/deepsecret-go/keys"
	"github.com/deepsecret-io/deepsecret-go/secrets"
	"github.com/deepsecret-io/deepsecret-go/trust"
	"github.com/spf13/cobra"

	"github.com/deepsecret-io/cli/internal/auth"
	"github.com/deepsecret-io/cli/internal/console"
	"github.com/deepsecret-io/cli/internal/errs"
	"github.com/deepsecret-io/cli/internal/fingerprint"
	"github.com/deepsecret-io/cli/internal/identity"
	"github.com/deepsecret-io/cli/internal/logging"
	"github.com/deepsecret-io/cli/internal/ui"
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
		Short: "List the keys this device accepted for other people, and your own",
		Long: `List the keys this device accepted for other people, and your own. With
an email, also show the safety number with them for each key sends go to.`,
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.MaximumNArgs(1)(cmd, args); err != nil {
				return err
			}
			if len(args) == 1 {
				return checkEmailArg(args[0])
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := auth.NewAuthenticatedClient()
			if err != nil {
				return err
			}
			email := ""
			if len(args) == 1 {
				email = args[0]
			}
			keyList, err := c.Trust.List(email)
			if err != nil {
				return err
			}
			if len(keyList) == 0 {
				ui.Dimmed("No known keys yet. The first secret to or from someone accepts their key.")
				return nil
			}
			ui.Header(fmt.Sprintf("Known keys (%d)", len(keyList)))
			fmt.Fprintln(os.Stderr)
			for _, k := range keyList {
				state := keyStateLabel(k.State)
				if k.Replaced {
					state += ", replaced"
				}
				fmt.Printf("  %-32s  %s  %-20s  %s\n", console.Safe(k.Email), console.Safe(keys.ShortFingerprint(k.Fingerprint)),
					state, k.FirstSeen.Local().Format("2006-01-02"))
			}
			fmt.Fprintln(os.Stderr)
			if email != "" {
				printKnownSafetyNumbers(cmd.Context(), email, keyList)
			}
			return nil
		},
	}
}

func newIdentityVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify <email> [fingerprint]",
		Short: "Compare someone's key with them, and mark it verified",
		Long: `Without a fingerprint, show the safety number of your primary key and the
key the server lists for <email>, that key's fingerprint in full, and the
keys this device accepted for them. Compare the number with them over a
channel you trust: they see the same number with secret identity verify
and your email.

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
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := auth.NewAuthenticatedClient()
			if err != nil {
				return err
			}
			email := args[0]
			if len(args) == 2 {
				if err := c.Trust.Verify(cmd.Context(), email, args[1]); err != nil {
					return err
				}
				logging.Module(logging.Log, "identity").Info("key verified", "email", email, "fingerprint", args[1])
				ui.Success(fmt.Sprintf("Marked key %s of %s as verified.", keys.ShortFingerprint(args[1]), email))
				return nil
			}

			current, err := c.Trust.ServerListedKeys(cmd.Context(), email)
			if err != nil {
				return err
			}
			known, err := c.Trust.List(email)
			if err != nil {
				return err
			}
			own, ownErr := ownSafetyKey(cmd.Context())
			printKeyCheck(email, current.Fingerprint, known, own, ownErr)
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
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := auth.NewAuthenticatedClient()
			if err != nil {
				return err
			}
			if err := c.Trust.Accept(cmd.Context(), args[0], args[1]); err != nil {
				return err
			}
			logging.Module(logging.Log, "identity").Info("key accepted", "email", args[0], "fingerprint", args[1])
			ui.Success(fmt.Sprintf("Accepted key %s for %s.", keys.ShortFingerprint(args[1]), args[0]))
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
			c, err := auth.NewAuthenticatedClient()
			if err != nil {
				return err
			}
			fp := ""
			if len(args) == 2 {
				fp = args[1]
			}
			n, err := c.Trust.Forget(args[0], fp)
			if err != nil {
				return err
			}
			if n == 0 {
				ui.Dimmed(fmt.Sprintf("This device knows no key to forget for %s.", args[0]))
				return nil
			}
			logging.Module(logging.Log, "identity").Info("keys forgotten", "email", args[0], "fingerprint", fp, "count", n)
			ui.Success(fmt.Sprintf("Forgot %d key%s of %s.", n, ui.PluralS(n), args[0]))
			return nil
		},
	}
}

// printKeyCheck prints identity verify <email>: the safety number of own,
// your primary key, and fp, the key the server lists for email, then that
// key's fingerprint and what this device knows of it. Without own (ownErr
// says why), the fingerprint alone is there to compare.
func printKeyCheck(email, fp string, known []trust.KnownKey, own string, ownErr error) {
	email = console.Safe(email)
	rows, err := []string(nil), ownErr
	if err == nil {
		rows, err = identity.PairSafetyRows(own, fp)
	}
	if err == nil {
		ui.Header("Safety number with " + email)
		fmt.Fprintln(os.Stderr)
		printSafetyRows(rows)
	} else {
		ui.Header("Key of " + email)
	}
	fmt.Fprintln(os.Stderr)
	ui.KeyValues("Key fingerprint", fingerprint.Group(fp))
	ui.KeyValue("This device", knownKeyStatus(fp, known))
	fmt.Fprintln(os.Stderr)
	if err == nil {
		ui.Dimmed(fmt.Sprintf("Compare the number with %s over a channel you trust.", email))
		ui.Dimmed(sameNumberHint(email))
	} else {
		ui.Dimmed(fmt.Sprintf("No safety number: %v.", err))
		ui.Dimmed(fmt.Sprintf("Compare the key fingerprint with %s over a channel you trust (they see theirs with: secret identity show).", email))
	}
	ui.Dimmed("If it matches, run:")
	ui.Dimmed(fmt.Sprintf("  secret identity verify %s %s", email, console.Safe(fp)))
	fmt.Fprintln(os.Stderr)
}

// checkEmailArg checks an email given as an argument.
func checkEmailArg(email string) error {
	return secrets.ValidateRecipients([]string{email})
}

// checkFullFingerprintArg checks args[i], a full fingerprint, and leaves it
// in lower case. A prefix is refused: accepting or verifying a key names
// exactly one.
func checkFullFingerprintArg(args []string, i int) error {
	fp, err := fingerprint.Check(args[i])
	if err != nil || len(fp) != keys.FingerprintLen {
		return fmt.Errorf("invalid fingerprint %q: give the full 64-character fingerprint", args[i])
	}
	args[i] = fp
	return nil
}

func keyStateLabel(s trust.State) string {
	switch s {
	case trust.FirstUse:
		return "first use"
	case trust.Accepted:
		return "accepted"
	case trust.Verified:
		return "verified"
	case trust.Own:
		return "yours"
	}
	return console.Safe(string(s))
}

// knownKeyStatus says what this device knows of fp, the key the server
// lists for someone whose accepted keys are known.
func knownKeyStatus(fp string, known []trust.KnownKey) string {
	if len(known) == 0 {
		return "not known yet: the first secret to or from them accepts it"
	}
	var current, all []string
	for _, k := range known {
		all = append(all, keys.ShortFingerprint(k.Fingerprint))
		if !k.Replaced {
			current = append(current, keys.ShortFingerprint(k.Fingerprint))
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
			return console.Yellow + "replaced" + console.Reset + " by " + strings.Join(current, ", ")
		}
		return keyStateLabel(k.State) + ", since " + k.FirstSeen.Local().Format("2006-01-02")
	}
	return console.Yellow + "changed" + console.Reset + " from " + strings.Join(current, ", ")
}

// printFirstUse notes, under a result block, keys accepted on first use:
// nothing yet shows they are their owners', so they are worth comparing.
func printFirstUse(people []secrets.Recipient) {
	for _, p := range people {
		email := console.Safe(p.Email)
		ui.Dimmed(fmt.Sprintf("First secret with %s on this device: their key %s is now the one expected. Compare the safety number with them: secret identity verify %s",
			email, console.Safe(keys.ShortFingerprint(p.Fingerprint)), email))
	}
	if len(people) > 0 {
		fmt.Fprintln(os.Stderr)
	}
}

// describeFailure is errs.Describe for a command's failure: a send or
// decrypt refused because someone's key changed also says how to check the
// new key and accept it.
func describeFailure(ctx context.Context, err error) (summary, detail string) {
	summary, detail = errs.Describe(err)
	extra := keyChangedDetail(ctx, err)
	if extra == "" {
		extra = kmsDetail(err)
	}
	switch {
	case extra == "":
		return summary, detail
	case detail == "":
		return summary, extra
	}
	return summary, detail + "\n\n" + extra
}

// keyChangedDetail is the detail of the Error block of a send or decrypt
// refused because someone's key changed: how to check the new key and
// accept it. With your primary key on this device, that is the safety
// number of it and the new key, with the new key's fingerprint under it;
// without, the fingerprint alone. It is "" for any other error.
func keyChangedDetail(ctx context.Context, err error) string {
	var changed *trust.KeyChangedError
	if !errors.As(err, &changed) {
		return ""
	}
	email, got := console.Safe(changed.Email), console.Safe(changed.Got)
	fp := fingerprint.Group(got)
	accept := fmt.Sprintf("If it matches, accept it and try again:\n\n  secret identity accept %s %s", email, got)
	own, err := ownSafetyKey(ctx)
	var rows []string
	if err == nil {
		rows, err = identity.PairSafetyRows(own, changed.Got)
	}
	if err != nil {
		return fmt.Sprintf("Ask %s for their key fingerprint over a channel you trust, and compare it with this one:\n\n"+
			"  %s\n  %s\n\n%s", email, fp[0], fp[1], accept)
	}
	return fmt.Sprintf("Compare the safety number with %s over a channel you trust. With the new key it is:\n\n"+
		"  %s\n\n"+
		"%s\n\n"+
		"Key fingerprint:\n\n  %s\n  %s\n\n%s",
		email, strings.Join(rows, "\n  "), sameNumberHint(email), fp[0], fp[1], accept)
}
