// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	deepsecret "github.com/deepsecret-io/deepsecret-go"
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
		Use:   "verify <email> [fingerprint | safety number]",
		Short: "Compare someone's key with them, and mark it verified",
		Long: `The first secret to or from someone locks this device to the key the
server gave for them; verifying checks that it is really theirs.

Without a fingerprint, show the safety number of your primary key and the
key the server lists for <email>, that key's fingerprint in full, and the
keys this device accepted for them. Compare the number with them over a
channel you trust: they see the same number with secret identity verify
and your email.

With the full fingerprint you compared, or the safety number itself, mark
that key verified, accepting it if this device did not know it. A key pair
on this device, for one of your own accounts, is already trusted.`,
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.MinimumNArgs(1)(cmd, args); err != nil {
				return err
			}
			if err := checkEmailArg(args[0]); err != nil {
				return err
			}
			if len(args) > 1 {
				_, err := parseVerifyKey(args[1:])
				return err
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := auth.NewAuthenticatedClient()
			if err != nil {
				return err
			}
			email := args[0]
			if len(args) > 1 {
				return verifyKeyOf(cmd.Context(), c, email, args[1:])
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

// verifyKeyOf marks email's key verified: the full fingerprint given, or
// the key the server lists for them when given its safety number, which
// must be the one this device computes for that key. A key pair on this
// device for one of the user's own accounts is already trusted.
func verifyKeyOf(ctx context.Context, c *deepsecret.Client, email string, given []string) error {
	key, err := parseVerifyKey(given)
	if err != nil {
		return err
	}
	known, err := c.Trust.List(email)
	if err != nil {
		return err
	}
	fp := key.fingerprint
	if key.safety != "" {
		current, err := c.Trust.ServerListedKeys(ctx, email)
		if err != nil {
			return err
		}
		fp = current.Fingerprint
		if !ownKeyOnDevice(known, fp) {
			own, err := ownSafetyKey(ctx)
			if err != nil {
				return errs.WithDetail(fmt.Errorf("no safety number to compare with: %w", err),
					fmt.Sprintf("Give the full key fingerprint instead, as secret identity verify %s shows it.", email))
			}
			rows, err := identity.PairSafetyRows(own, fp)
			if err != nil {
				return err
			}
			if err := checkSafetyNumber(rows, key.safety, email); err != nil {
				return err
			}
		}
	}
	if ownKeyOnDevice(known, fp) {
		ui.Success(fmt.Sprintf("Nothing to verify: key %s of %s is a key pair on this device, one of your own accounts, so it is already trusted.",
			keys.ShortFingerprint(fp), email))
		return nil
	}
	if err := c.Trust.Verify(ctx, email, fp); err != nil {
		return err
	}
	logging.Module(logging.Log, "identity").Info("key verified", "email", email, "fingerprint", fp)
	ui.Success(fmt.Sprintf("Marked key %s of %s as verified.", keys.ShortFingerprint(fp), email))
	return nil
}

// verifyKey is the key verify was given: a full fingerprint, or the
// safety number verify showed, in digits.
type verifyKey struct {
	fingerprint string
	safety      string
}

// parseVerifyKey reads the arguments after the email: the full key
// fingerprint, or the safety number, each as one argument or in the groups
// verify shows it in.
func parseVerifyKey(args []string) (verifyKey, error) {
	joined := strings.Join(strings.Fields(strings.Join(args, " ")), "")
	if fp, err := fingerprint.Check(joined); err == nil && len(fp) == keys.FingerprintLen {
		return verifyKey{fingerprint: fp}, nil
	}
	if joined != "" && strings.Trim(joined, "0123456789") == "" {
		return verifyKey{safety: joined}, nil
	}
	return verifyKey{}, fmt.Errorf("give the full 64-character key fingerprint, or the safety number, as secret identity verify <email> shows them")
}

// checkSafetyNumber checks given, the digits of a safety number, against
// rows, the safety number this device computes for the key the server
// lists for email.
func checkSafetyNumber(rows []string, given, email string) error {
	want := strings.Join(strings.Fields(strings.Join(rows, " ")), "")
	if len(given) != len(want) {
		return errs.WithDetail(fmt.Errorf("the safety number has %d digits, and %d were given", len(want), len(given)),
			fmt.Sprintf("Give all %d groups of five digits, as secret identity verify %s shows them, or the full key fingerprint.", len(want)/5, email))
	}
	if given != want {
		return errs.WithDetail(fmt.Errorf("the safety number does not match the key the server lists for %s", email),
			fmt.Sprintf("Do not verify it. Check that you compared the whole number with %s, and that they read it with: secret identity verify <your email>. "+
				"If you both did and the numbers differ, someone may be giving one of you a different key.", email))
	}
	return nil
}

// ownKeyOnDevice reports whether fp is a key pair on this device for one
// of the user's own accounts, which needs no verifying.
func ownKeyOnDevice(known []trust.KnownKey, fp string) bool {
	return slices.ContainsFunc(known, func(k trust.KnownKey) bool { return k.State == trust.Own && k.Fingerprint == fp })
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
	if ownKeyOnDevice(known, fp) {
		ui.Dimmed("This key pair is on this device, for one of your own accounts: it is already trusted, and there is nothing to compare.")
		fmt.Fprintln(os.Stderr)
		return
	}
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
// new key and accept it, and one refused because a key was relabelled, what
// to confirm before forgetting its old record.
func describeFailure(ctx context.Context, err error) (summary, detail string) {
	summary, detail = errs.Describe(err)
	extra := keyChangedDetail(ctx, err)
	if extra == "" {
		extra = keyRelabelledDetail(err)
	}
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

// keyRelabelledDetail is the detail of the Error block of a send, a
// decrypt or an accept refused because the server presents, for one
// address, a key this device recorded for another: the server may be
// passing one person's key off as someone else's. Only the person the key
// is recorded for can say they changed address, and then forgetting that
// one record lets the key pass for the new address.
//
// A send refused because the server lists one key for two of its
// recipients, both new to this device (SameSend), has no record to forget:
// the detail says so, and to check both addresses first. It is "" for any
// other error.
func keyRelabelledDetail(err error) string {
	var relabelled *trust.KeyRelabelledError
	if !errors.As(err, &relabelled) {
		return ""
	}
	email, recorded := console.Safe(relabelled.Email), console.Safe(relabelled.RecordedEmail)
	if relabelled.SameSend {
		return fmt.Sprintf("The server listed the same key for %s and %s. A key belongs to one address, so the send was refused. "+
			"Nothing was recorded on this device, so there is nothing to forget.\n\n"+
			"Check both addresses with those people over a channel you trust, or with the operator of the server, before sending again.", recorded, email)
	}
	return fmt.Sprintf("The server presents, for %[1]s, a key this device knows as %[2]s's. A key belongs to one address, so the server may be relabelling it.\n\n"+
		"Do not continue unless %[2]s confirms, over a channel you trust, that they changed their address to %[1]s. "+
		"If they did, forget the old record and try again:\n\n"+
		"  secret identity forget %[2]s %[3]s", email, recorded, console.Safe(relabelled.Fingerprint))
}
