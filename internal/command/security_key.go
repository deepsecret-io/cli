// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/deepsecret-io/sdk"
	"github.com/deepsecret-io/sdk/api"
	"github.com/deepsecret-io/sdk/crypto"
	"github.com/spf13/cobra"

	"github.com/deepsecret-io/cli/internal/auth"
	"github.com/deepsecret-io/cli/internal/config"
	"github.com/deepsecret-io/cli/internal/console"
	"github.com/deepsecret-io/cli/internal/errs"
	"github.com/deepsecret-io/cli/internal/flags"
	"github.com/deepsecret-io/cli/internal/identity"
	"github.com/deepsecret-io/cli/internal/logging"
	"github.com/deepsecret-io/cli/internal/prompt"
	"github.com/deepsecret-io/cli/internal/ui"
)

// refreshSecurityKeyLabel brings the security key label of the registered
// key k up to date with the key pair name on this device, for identity
// sync on a key that is registered already.
func refreshSecurityKeyLabel(ctx context.Context, c *sdk.Client, k *sdk.RemoteKey, name string) error {
	want := identity.Protection(name) == crypto.ProtectionSecurityKey
	short := crypto.ShortFingerprint(name)
	if k.SecurityKey != want {
		if err := c.SetKeySecurityKey(ctx, k.ID, want); err != nil {
			return fmt.Errorf("could not update the label of key %s: %w", short, errs.APICause(err))
		}
		api.Module(logging.Log, "identity").Info("security key label updated", "fingerprint", name, "security_key", want)
	}
	if want {
		ui.Success("Key " + short + " is registered, labelled as protected by a security key")
	} else {
		ui.Success("Key " + short + " is registered")
	}
	if !k.IsPrimary {
		ui.Dimmed("To make it your primary key: secret identity set-primary " + name)
	}
	return nil
}

// reportProtection updates the security key label of the key pair name on
// the server after its protection changed here, when it is registered and
// the CLI is signed in, so the user's key lists (the web app's among them)
// show it. The local change stands either way: a failure is only told.
func reportProtection(ctx context.Context, name string) {
	c, err := auth.NewAuthenticatedClient()
	if err != nil {
		return // not signed in: nothing registered can be updated from here
	}
	want := identity.Protection(name) == crypto.ProtectionSecurityKey
	keys, err := c.ListRemoteKeys(ctx)
	var k *sdk.RemoteKey
	if err == nil {
		if k = identity.Registered(keys, name); k == nil || k.SecurityKey == want {
			return
		}
		err = c.SetKeySecurityKey(ctx, k.ID, want)
	}
	if err != nil {
		ui.Dimmed("Your key lists could not be told about the change (" + console.Safe(errs.APICause(err).Error()) + "). Later: secret identity sync -i " + name)
		return
	}
	api.Module(logging.Log, "identity").Info("security key label updated", "fingerprint", name, "security_key", want)
}

// saveWithSecurityKey writes a new key pair straight to a security-key
// file, after enrolling its security key and the second way in: it is
// never on disk unprotected.
func saveWithSecurityKey(ctx context.Context, kp *crypto.KeyPair, label string, backup, recovery, single bool) error {
	e, err := crypto.NewSecurityKeyFile(config.KeysDir(), kp)
	if err != nil {
		return fmt.Errorf("could not save the key pair: %w", err)
	}
	defer e.Close()
	if err := enrollWays(ctx, e, label, backup, recovery); err != nil {
		return err
	}
	if err := e.Commit(single); err != nil {
		if recovery {
			return notSaved(err)
		}
		return fmt.Errorf("could not save the key pair: %w", err)
	}
	logProtected(e, "generated with a security key")
	return nil
}

// commandUnlock works out how the key pair a command signs or decrypts
// with is unlocked, and asks only for what its file needs: nothing, its
// password, or its recovery code when useRecovery is set. A security key is
// asked for its PIN and a touch by the SDK, once, when the key is used.
// identityFP empty means the primary key.
func commandUnlock(ctx context.Context, c *sdk.Client, identityFP string, useRecovery bool) (crypto.Unlock, error) {
	primary := identityFP == ""
	name := ""
	if primary {
		fp, err := c.PrimaryFingerprint(ctx)
		if err != nil {
			return crypto.Unlock{}, fmt.Errorf("could not load your primary key: %w", err)
		}
		name = identity.ResolveFile(fp)
	} else {
		name = identity.ResolveFile(identityFP)
	}
	info, err := crypto.ReadKeyFileInfo(config.KeysDir(), name)
	if err != nil {
		if primary {
			return crypto.Unlock{}, fmt.Errorf("could not load your primary key: %w", err)
		}
		return crypto.Unlock{}, nil // loading the key reports it
	}
	if useRecovery && info.Protection != crypto.ProtectionSecurityKey {
		return crypto.Unlock{}, fmt.Errorf("--recovery-code: key pair %s is not protected by a security key", crypto.ShortFingerprint(info.Fingerprint))
	}
	switch info.Protection {
	case crypto.ProtectionPassword:
		if !primary {
			pw, err := prompt.Password(ctx, fmt.Sprintf("Password for key pair %s: ", crypto.ShortFingerprint(name)))
			return crypto.Unlock{Password: pw}, err
		}
		pw, err := prompt.Password(ctx, "Password for your primary key: ")
		if err != nil {
			return crypto.Unlock{}, err
		}
		if _, _, err := c.LoadPrimaryIdentity(ctx, pw); err != nil {
			return crypto.Unlock{}, fmt.Errorf("could not unlock your primary key: %w", err)
		}
		return crypto.Unlock{Password: pw}, nil
	case crypto.ProtectionSecurityKey:
		if err := identity.RequireTerminal(info.Fingerprint); err != nil {
			return crypto.Unlock{}, err
		}
		if useRecovery {
			code, err := prompt.Password(ctx, fmt.Sprintf("Recovery code for key pair %s: ", crypto.ShortFingerprint(info.Fingerprint)))
			return crypto.Unlock{RecoveryCode: code}, err
		}
		return crypto.Unlock{SecurityKey: identity.SecurityKey()}, nil
	}
	return crypto.Unlock{}, nil
}

// showRecoveryCode shows a new recovery code once, on the terminal only,
// and asks for two of its groups back, so it is known to be written down.
func showRecoveryCode(ctx context.Context, code string) error {
	out, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return errors.New("a recovery code is shown only on a terminal; run the command in one")
	}
	defer func() { _ = out.Close() }()
	_, _ = fmt.Fprintf(out, "\n  Recovery code (shown once; write it down and keep it apart from your security keys):\n\n      %s\n\n"+
		"  It unlocks the key pair without a security key. Anyone who has it and a copy of the key file can too.\n\n", code)
	groups := strings.Split(code, "-")
	first, second := randomIndex(len(groups)), randomIndex(len(groups)-1)
	if second >= first {
		second++
	}
	if first > second {
		first, second = second, first
	}
	for attempt := 0; attempt < 3; attempt++ {
		ok := true
		for _, i := range []int{first, second} {
			typed, err := prompt.Line(ctx, fmt.Sprintf("Type group %d of the recovery code: ", i+1))
			if err != nil {
				return errs.WithDetail(err, recoveryCodeNotSaved)
			}
			if crypto.NormalizeRecoveryCode(typed) != groups[i] {
				ok = false
			}
		}
		if ok {
			_, _ = fmt.Fprint(out, "\033[2J\033[H") // clear the screen, so the code does not stay on it
			return nil
		}
		_, _ = fmt.Fprintln(out, "  That does not match. Check what you wrote down.")
	}
	return errors.New("the recovery code was not confirmed; nothing was changed")
}

func randomIndex(n int) int {
	i, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(i.Int64())
}

// keyToProtect is the key pair a security key command changes: the one -i
// names, else the only one on this device, else the primary key.
func keyToProtect(ctx context.Context, identityFP string) (string, error) {
	if identityFP != "" {
		return identity.ResolveName(identityFP)
	}
	names, err := identity.List()
	if err != nil {
		return "", fmt.Errorf("could not list the key pairs on this device: %w", err)
	}
	switch len(names) {
	case 0:
		return "", errs.WithDetail(errors.New("there is no key pair on this device"), "Create one with: secret identity generate --security-key --recovery-code")
	case 1:
		return names[0], nil
	}
	if name := identity.PrimaryLocal(ctx, names); name != "" {
		return name, nil
	}
	return "", errs.WithDetail(fmt.Errorf("there are %d key pairs on this device", len(names)), "Choose one with -i; list them with: secret identity list")
}

// unlockForEdit unlocks a security-key protected key pair to change its
// slots: with the security key, or with the recovery code.
func unlockForEdit(ctx context.Context, name string, useRecovery bool) (*crypto.SlotEditor, error) {
	info, err := crypto.ReadKeyFileInfo(config.KeysDir(), name)
	if err != nil {
		return nil, fmt.Errorf("could not read key pair %s: %w", crypto.ShortFingerprint(name), err)
	}
	if info.Protection != crypto.ProtectionSecurityKey {
		return nil, errs.WithDetail(fmt.Errorf("key pair %s is not protected by a security key", crypto.ShortFingerprint(name)),
			"Protect it with: secret identity security-key protect -i "+crypto.ShortFingerprint(name))
	}
	if err := identity.RequireTerminal(name); err != nil {
		return nil, err
	}
	u := crypto.Unlock{SecurityKey: identity.SecurityKey()}
	if useRecovery {
		code, err := prompt.Password(ctx, fmt.Sprintf("Recovery code for key pair %s: ", crypto.ShortFingerprint(name)))
		if err != nil {
			return nil, err
		}
		u = crypto.Unlock{RecoveryCode: code}
	}
	return crypto.EditKeyFile(ctx, config.KeysDir(), name, u)
}

// enrollWays adds the security key connected to e, then the second way in
// the flags ask for: a backup security key, a recovery code, or none
// (single). It writes nothing.
func enrollWays(ctx context.Context, e *crypto.SlotEditor, label string, backup, recovery bool) error {
	fmt.Fprintln(os.Stderr, "Leave only the security key to enroll plugged in.")
	slot, err := e.AddSecurityKey(ctx, identity.SecurityKey(), label)
	if err != nil {
		return fmt.Errorf("could not enroll the security key: %w", err)
	}
	ui.Success("Enrolled " + console.Safe(slot.Label))
	if backup {
		if _, err := prompt.Line(ctx, "Unplug it, plug in the backup security key, then press Enter: "); err != nil {
			return err
		}
		slot, err := e.AddSecurityKey(ctx, identity.SecurityKey(), "")
		if err != nil {
			return fmt.Errorf("could not enroll the backup security key: %w", err)
		}
		ui.Success("Enrolled " + console.Safe(slot.Label) + " as a backup")
	}
	if recovery {
		code, err := e.SetRecoveryCode()
		if err != nil {
			return err
		}
		if err := showRecoveryCode(ctx, code); err != nil {
			return err
		}
	}
	return nil
}

// notSaved explains, after a failed save, that a recovery code already
// shown opens nothing.
func notSaved(err error) error {
	return errs.WithDetail(fmt.Errorf("could not save the key pair: %w", err), recoveryCodeNotSaved)
}

// recoveryCodeNotSaved is what a command that stops after showing a recovery
// code says about it: the code opens nothing.
const recoveryCodeNotSaved = "Nothing was changed. The recovery code shown above was not saved: discard it."

// checkSecondWay refuses before any touch when the flags give no second
// way in and no waiver.
func checkSecondWay(backup, recovery, single bool) error {
	if backup || recovery || single {
		return nil
	}
	return errs.WithDetail(errors.New("a security key needs a second way in, in case it is lost"),
		"Add --backup to enroll a second security key, or --recovery-code to get a printed code.\n"+
			"With --single the key pair is lost for good if the security key is lost.")
}

func newIdentitySecurityKeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "security-key",
		Aliases: []string{"sk"},
		Short:   "Protect a key pair with a security key such as a YubiKey",
		Long: "A key pair protected by a security key opens only with an enrolled FIDO2 security key\n" +
			"(its PIN and a touch) or its recovery code: a copy of the key file alone is useless.\n" +
			"It needs libfido2 (macOS: brew install libfido2; Debian and Ubuntu: apt install libfido2-1).",
	}
	cmd.AddCommand(newSecurityKeyProtectCmd(), newSecurityKeyAddCmd(), newSecurityKeyListCmd(),
		newSecurityKeyRemoveCmd(), newSecurityKeyRecoveryCodeCmd(), newSecurityKeyUnprotectCmd())
	return cmd
}

func newSecurityKeyProtectCmd() *cobra.Command {
	var identityFP, label string
	var backup, recovery, single bool
	cmd := &cobra.Command{
		Use:   "protect",
		Short: "Protect a key pair with a security key, in place of its password",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := checkSecondWay(backup, recovery, single); err != nil {
				return err
			}
			name, err := keyToProtect(cmd.Context(), identityFP)
			if err != nil {
				return err
			}
			info, err := crypto.ReadKeyFileInfo(config.KeysDir(), name)
			if err != nil {
				return fmt.Errorf("could not read key pair %s: %w", crypto.ShortFingerprint(name), err)
			}
			if info.Protection == crypto.ProtectionSecurityKey {
				return errs.WithDetail(fmt.Errorf("key pair %s is already protected by a security key", crypto.ShortFingerprint(name)),
					"Add another with: secret identity security-key add -i "+crypto.ShortFingerprint(name))
			}
			if err := identity.RequireTerminal(""); err != nil {
				return err
			}
			var pw string
			if info.Protection == crypto.ProtectionPassword {
				if pw, err = prompt.Password(cmd.Context(), fmt.Sprintf("Password for key pair %s: ", crypto.ShortFingerprint(name))); err != nil {
					return err
				}
			}
			e, err := crypto.EditKeyFile(cmd.Context(), config.KeysDir(), name, crypto.Unlock{Password: pw})
			if err != nil {
				return fmt.Errorf("could not unlock key pair %s: %w", crypto.ShortFingerprint(name), err)
			}
			defer e.Close()
			if err := enrollWays(cmd.Context(), e, label, backup, recovery); err != nil {
				return err
			}
			if err := e.Commit(single); err != nil {
				if recovery {
					return notSaved(err)
				}
				return fmt.Errorf("could not save the key pair: %w", err)
			}
			logProtected(e, "protected")
			ui.Success("Key pair " + crypto.ShortFingerprint(name) + " is protected by a security key")
			reportProtection(cmd.Context(), name)
			if info.Protection == crypto.ProtectionPassword {
				ui.Dimmed("Its password no longer opens it. Copies of the key file made before now (backups) still open with the password alone.")
			} else {
				ui.Dimmed("Copies of the key file made before now (backups) are still unprotected.")
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&identityFP, "identity", "i", "", "The key pair to protect (default: the only one, or your primary key)")
	cmd.Flags().StringVar(&label, "label", "", "A name for the security key (default: its product name)")
	cmd.Flags().BoolVar(&backup, "backup", false, "Also enroll a backup security key")
	cmd.Flags().BoolVar(&recovery, "recovery-code", false, "Also create a printed recovery code")
	cmd.Flags().BoolVar(&single, "single", false, "Allow one security key with no backup and no recovery code")
	flags.SetGroup(cmd.Flags(), flags.GroupOptions, "identity", "label", "backup", "recovery-code", "single")
	return cmd
}

func newSecurityKeyAddCmd() *cobra.Command {
	var identityFP, label string
	var useRecovery bool
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Enroll another security key, such as a backup",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			name, err := keyToProtect(cmd.Context(), identityFP)
			if err != nil {
				return err
			}
			e, err := unlockForEdit(cmd.Context(), name, useRecovery)
			if err != nil {
				return err
			}
			defer e.Close()
			if !useRecovery {
				if _, err := prompt.Line(cmd.Context(), "Unplug the security key you just used, plug in the new one, then press Enter: "); err != nil {
					return err
				}
			}
			slot, err := e.AddSecurityKey(cmd.Context(), identity.SecurityKey(), label)
			if err != nil {
				return fmt.Errorf("could not enroll the security key: %w", err)
			}
			if err := e.Commit(true); err != nil {
				return fmt.Errorf("could not save the key pair: %w", err)
			}
			logProtected(e, "security key added")
			ui.Success("Enrolled " + console.Safe(slot.Label) + " for key pair " + crypto.ShortFingerprint(name))
			return nil
		},
	}
	cmd.Flags().StringVarP(&identityFP, "identity", "i", "", "The key pair (default: the only one, or your primary key)")
	cmd.Flags().StringVar(&label, "label", "", "A name for the security key (default: its product name)")
	cmd.Flags().BoolVar(&useRecovery, "recovery-code", false, "Unlock with the recovery code instead of a security key")
	flags.SetGroup(cmd.Flags(), flags.GroupOptions, "identity", "label", "recovery-code")
	return cmd
}

func newSecurityKeyListCmd() *cobra.Command {
	var identityFP string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the ways into a key pair, without unlocking it",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			name, err := keyToProtect(cmd.Context(), identityFP)
			if err != nil {
				return err
			}
			info, err := crypto.ReadKeyFileInfo(config.KeysDir(), name)
			if err != nil {
				return fmt.Errorf("could not read key pair %s: %w", crypto.ShortFingerprint(name), err)
			}
			ui.Header("Key pair " + crypto.ShortFingerprint(info.Fingerprint))
			fmt.Fprintln(os.Stderr)
			switch info.Protection {
			case crypto.ProtectionNone:
				ui.KeyValue("Protection", "none: the private keys are stored in clear")
			case crypto.ProtectionPassword:
				ui.KeyValue("Protection", "password")
			default:
				ui.KeyValue("Protection", "security key")
				for _, s := range info.Slots {
					kind := "security key"
					if s.Type == crypto.SlotRecoveryCode {
						kind = "recovery code"
					}
					fmt.Printf("  %s  %-13s  %s  (added %s)\n", s.ID, kind, console.Safe(s.Label), s.CreatedAt.Local().Format(time.DateOnly))
				}
			}
			fmt.Fprintln(os.Stderr)
			return nil
		},
	}
	cmd.Flags().StringVarP(&identityFP, "identity", "i", "", "The key pair (default: the only one, or your primary key)")
	flags.SetGroup(cmd.Flags(), flags.GroupOptions, "identity")
	return cmd
}

func newSecurityKeyRemoveCmd() *cobra.Command {
	var identityFP string
	var useRecovery, single bool
	cmd := &cobra.Command{
		Use:   "remove <slot-id>",
		Short: "Remove a security key or the recovery code (ids from: secret identity security-key list)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, err := keyToProtect(cmd.Context(), identityFP)
			if err != nil {
				return err
			}
			info, err := crypto.ReadKeyFileInfo(config.KeysDir(), name)
			if err != nil {
				return fmt.Errorf("could not read key pair %s: %w", crypto.ShortFingerprint(name), err)
			}
			var target *crypto.SlotInfo
			for i := range info.Slots {
				if info.Slots[i].ID == args[0] {
					target = &info.Slots[i]
				}
			}
			if target == nil {
				return errs.WithDetail(fmt.Errorf("key pair %s has no slot %s", crypto.ShortFingerprint(name), console.Safe(args[0])),
					"List them with: secret identity security-key list -i "+crypto.ShortFingerprint(name))
			}
			e, err := unlockForEdit(cmd.Context(), name, useRecovery)
			if err != nil {
				return err
			}
			defer e.Close()
			if err := e.Remove(target.ID); err != nil {
				return err
			}
			if err := e.Commit(single); err != nil {
				return fmt.Errorf("could not save the key pair: %w", err)
			}
			logProtected(e, "slot removed")
			ui.Success("Removed " + console.Safe(target.Label) + " from key pair " + crypto.ShortFingerprint(name))
			ui.Dimmed("Copies of the key file made before now still open with it. If it was lost or seen by someone else,")
			ui.Dimmed("generate a new key pair and make it your primary key: secret identity generate --security-key --recovery-code")
			return nil
		},
	}
	cmd.Flags().StringVarP(&identityFP, "identity", "i", "", "The key pair (default: the only one, or your primary key)")
	cmd.Flags().BoolVar(&useRecovery, "recovery-code", false, "Unlock with the recovery code instead of a security key")
	cmd.Flags().BoolVar(&single, "single", false, "Allow leaving one security key with no backup and no recovery code")
	flags.SetGroup(cmd.Flags(), flags.GroupOptions, "identity", "recovery-code", "single")
	return cmd
}

func newSecurityKeyRecoveryCodeCmd() *cobra.Command {
	var identityFP string
	var useRecovery bool
	cmd := &cobra.Command{
		Use:   "recovery-code",
		Short: "Create a recovery code, replacing the current one",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			name, err := keyToProtect(cmd.Context(), identityFP)
			if err != nil {
				return err
			}
			e, err := unlockForEdit(cmd.Context(), name, useRecovery)
			if err != nil {
				return err
			}
			defer e.Close()
			code, err := e.SetRecoveryCode()
			if err != nil {
				return err
			}
			if err := showRecoveryCode(cmd.Context(), code); err != nil {
				return err
			}
			if err := e.Commit(false); err != nil {
				return notSaved(err)
			}
			logProtected(e, "recovery code set")
			ui.Success("New recovery code saved for key pair " + crypto.ShortFingerprint(name) + "; the old one no longer opens it")
			return nil
		},
	}
	cmd.Flags().StringVarP(&identityFP, "identity", "i", "", "The key pair (default: the only one, or your primary key)")
	cmd.Flags().BoolVar(&useRecovery, "recovery-code", false, "Unlock with the current recovery code instead of a security key")
	flags.SetGroup(cmd.Flags(), flags.GroupOptions, "identity", "recovery-code")
	return cmd
}

func newSecurityKeyUnprotectCmd() *cobra.Command {
	var identityFP string
	var useRecovery, noPassword bool
	cmd := &cobra.Command{
		Use:   "unprotect",
		Short: "Take security key protection off, back to a password",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			name, err := keyToProtect(cmd.Context(), identityFP)
			if err != nil {
				return err
			}
			e, err := unlockForEdit(cmd.Context(), name, useRecovery)
			if err != nil {
				return err
			}
			defer e.Close()
			pw := ""
			if !noPassword {
				if pw, err = prompt.PasswordConfirm(cmd.Context(), "New key password: "); err != nil {
					return err
				}
				if pw == "" {
					return errors.New("a password is needed; use --no-password to store the key pair unprotected")
				}
			}
			if err := e.CommitPassword(pw); err != nil {
				return fmt.Errorf("could not save the key pair: %w", err)
			}
			api.Module(logging.Log, "identity").Info("security key protection removed", "fingerprint", e.Fingerprint(), "password", !noPassword)
			ui.Success("Key pair " + crypto.ShortFingerprint(name) + " no longer needs a security key")
			ui.Warning("A copy of the key file can be guessed at offline again", "Its security keys and recovery code no longer open it; its password does.")
			reportProtection(cmd.Context(), name)
			return nil
		},
	}
	cmd.Flags().StringVarP(&identityFP, "identity", "i", "", "The key pair (default: the only one, or your primary key)")
	cmd.Flags().BoolVar(&useRecovery, "recovery-code", false, "Unlock with the recovery code instead of a security key")
	cmd.Flags().BoolVar(&noPassword, "no-password", false, "Store the private keys in clear")
	flags.SetGroup(cmd.Flags(), flags.GroupOptions, "identity", "recovery-code", "no-password")
	return cmd
}

// logProtected records a change to a key pair's slots: the slots by type,
// never anything secret.
func logProtected(e *crypto.SlotEditor, what string) {
	keys, codes := 0, 0
	for _, s := range e.Slots() {
		if s.Type == crypto.SlotSecurityKey {
			keys++
		} else {
			codes++
		}
	}
	api.Module(logging.Log, "identity").Info("key pair "+what, "fingerprint", e.Fingerprint(), "security_keys", keys, "recovery_codes", codes)
}
