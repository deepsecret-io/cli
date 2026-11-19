// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	deepsecret "github.com/deepsecret-io/deepsecret-go"
	sdkidentity "github.com/deepsecret-io/deepsecret-go/identity"
	"github.com/deepsecret-io/deepsecret-go/keys"
	"github.com/deepsecret-io/deepsecret-go/keystore"
	"github.com/spf13/cobra"

	"github.com/deepsecret-io/cli/internal/auth"
	"github.com/deepsecret-io/cli/internal/config"
	"github.com/deepsecret-io/cli/internal/console"
	"github.com/deepsecret-io/cli/internal/errs"
	"github.com/deepsecret-io/cli/internal/fingerprint"
	"github.com/deepsecret-io/cli/internal/flags"
	"github.com/deepsecret-io/cli/internal/identity"
	"github.com/deepsecret-io/cli/internal/logging"
	"github.com/deepsecret-io/cli/internal/prompt"
	"github.com/deepsecret-io/cli/internal/ui"
)

func newIdentityCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "identity",
		Aliases: []string{"id"},
		Short:   "Manage your key pairs and the keys you know (alias: id)",
	}

	cmd.AddCommand(
		newIdentityGenerateCmd(),
		newIdentityListCmd(),
		newIdentitySyncCmd(),
		newIdentityShowCmd(),
		newIdentitySetPrimaryCmd(),
		newIdentityKnownCmd(),
		newIdentityVerifyCmd(),
		newIdentityAcceptCmd(),
		newIdentityForgetCmd(),
		newIdentitySecurityKeyCmd(),
		newIdentityKMSCmd(),
		newIdentityImportCmd(),
	)

	return cmd
}

// The terminal a new key password is typed on: keyPasswordTerminal says
// whether there is one, and newKeyPassword reads and confirms the password
// there, without echo. Tests replace them.
var (
	keyPasswordTerminal = func() bool {
		t, err := prompt.OpenTerminal()
		if err != nil {
			return false
		}
		_ = t.Close()
		return true
	}
	newKeyPassword = prompt.PasswordConfirm
)

func newIdentityGenerateCmd() *cobra.Command {
	var usePassword, noPassword bool
	var local bool
	var useSecurityKey, backup, recoveryCode, single bool
	var label string
	var kmsARNs []string

	cmd := &cobra.Command{
		Use:     "generate",
		Aliases: []string{"gen"},
		Short:   "Generate a new key pair and make it your primary key (alias: gen)",
		Long: "Generate a new key pair on this device, register its public keys and make it your\n" +
			"primary key, the one people send to. With --local it stays on this device only;\n" +
			"register it later with: secret identity sync\n\n" +
			"The private keys are protected by a password, asked for twice on the terminal, unless\n" +
			"--security-key or --kms-arn protects them instead. The password is never read from a\n" +
			"flag, the environment or a pipe: where there is no terminal, choose --kms-arn, or\n" +
			"--no-password, which stores the private keys in clear, so that anyone who can read the\n" +
			"key file can open every secret sent to this identity.",
		Example: `  secret identity generate                                    # asks for a new password
  secret identity generate --security-key --recovery-code     # a security key, and a printed code if it is lost
  secret identity generate --kms-arn <KMS key ARN> --single   # AWS KMS, for automation
  secret identity generate --no-password                      # private keys stored in clear`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			useKMS := len(kmsARNs) > 0
			switch {
			case noPassword && (usePassword || useSecurityKey || useKMS):
				return errors.New("--no-password stores the private keys in clear: it does not go with --password, --security-key or --kms-arn")
			case useKMS && useSecurityKey:
				return errors.New("--kms-arn and --security-key do not go together: a key file holds KMS keys or security keys, never both")
			case useKMS && usePassword:
				return errors.New("--kms-arn and --password do not go together: the KMS key replaces the password")
			case useKMS && backup:
				return errors.New("--backup enrolls a second security key; for a second KMS key, repeat --kms-arn")
			case !useKMS && !useSecurityKey && (label != "" || backup || recoveryCode || single):
				return errors.New("--label, --backup, --recovery-code and --single go with --security-key or --kms-arn")
			}
			if useSecurityKey {
				if usePassword {
					return errors.New("--security-key and --password do not go together: the security key replaces the password")
				}
				if err := checkSecondWay(backup, recoveryCode, single); err != nil {
					return err
				}
				if err := identity.RequireTerminal(""); err != nil {
					return err
				}
			}
			if useKMS {
				if err := checkKMSWays(kmsARNs, recoveryCode, single); err != nil {
					return err
				}
				if err := checkKMSLabel(label); err != nil {
					return err
				}
				if recoveryCode {
					if err := requireCodeTerminal(); err != nil {
						return err
					}
				}
			}
			// A key pair is protected unless --no-password says otherwise:
			// with no other choice it gets a password, typed on the terminal
			// and nowhere else. With no terminal nothing is asked, generated
			// or written.
			if !useSecurityKey && !useKMS && !noPassword {
				if !keyPasswordTerminal() {
					return errs.WithDetail(errors.New("the password of a new key pair is typed on a terminal"),
						"Run the command in a terminal, or choose another way to store the private keys:\n"+
							"  secret identity generate --kms-arn <KMS key ARN> --single   protected by AWS KMS, for automation\n"+
							"  secret identity generate --security-key --recovery-code     protected by a security key (needs a terminal too)\n"+
							"  secret identity generate --no-password                      stored in clear")
				}
				usePassword = true
			}
			// A new key pair is registered unless --local: check the account
			// first, with a request, so a missing or revoked login fails
			// before any PIN or touch and does not leave a key pair saved but
			// not registered. A KMS key binds the key pair to the account, so
			// it needs the account even with --local.
			var c *deepsecret.Client
			var account string
			if useKMS {
				var err error
				if c, account, err = kmsAccount(cmd.Context()); err != nil {
					return err
				}
			}
			if !local {
				const localHint = "To keep the key pair on this device only, without registering it:\n  secret identity generate --local"
				var err error
				if c == nil {
					if c, err = auth.NewAuthenticatedClient(); err != nil {
						return errs.WithDetail(err, strings.TrimSpace(errs.JoinDetail("", err)+"\n\n"+localHint))
					}
				}
				if _, err := c.Identity.ListKeys(cmd.Context()); err != nil {
					err = fmt.Errorf("could not reach your account to register the key pair: %w", errs.APICause(err))
					return errs.WithDetail(err, strings.TrimSpace(errs.JoinDetail("", err)+"\n\n"+localHint))
				}
				if err := checkProtectionPolicy(cmd.Context(), c, usePassword || useSecurityKey || useKMS); err != nil {
					return err
				}
			}
			var password string
			if usePassword {
				var err error
				password, err = newKeyPassword(cmd.Context(), "Set key password: ")
				if err != nil {
					return err
				}
				if password == "" {
					return errors.New("a password is needed; use --no-password to store the key pair unprotected")
				}
			}

			var kp *keys.Pair
			var fp string
			steps := []ui.Step{
				{
					Label: "Generating a hybrid key pair",
					Done:  "Key pair generated",
					Action: func() (string, error) {
						var err error
						if kp, err = keys.Generate(); err != nil {
							return "", fmt.Errorf("could not generate a key pair: %w", err)
						}
						if fp, err = keys.Fingerprint(kp); err != nil {
							return "", fmt.Errorf("could not compute the key pair's fingerprint: %w", err)
						}
						if identity.Exists(fp) {
							return "", fmt.Errorf("a key pair with fingerprint %s already exists", fp)
						}
						return "fingerprint=" + keys.ShortFingerprint(fp), nil
					},
				},
				{
					Label: "Saving the key pair",
					Done:  "Key pair saved",
					Action: func() (string, error) {
						if err := identity.SaveKeyPair(fp, kp, password); err != nil {
							return "", fmt.Errorf("could not save the key pair: %w", err)
						}
						logging.Module(logging.Log, "identity").Info("key pair generated", "fingerprint", fp, "encrypted", usePassword)
						if usePassword {
							return "encrypted=true", nil
						}
						return "", nil
					},
				},
			}
			if !local {
				steps = append(steps,
					ui.Step{
						Label: "Signing and uploading the public keys",
						Done:  "Public keys uploaded",
						Action: func() (string, error) {
							return registerKeyPair(cmd.Context(), c, kp, fp)
						},
					},
					setPrimaryStep(cmd.Context(), c, &fp),
				)
			}

			run := steps
			var after []ui.Step
			if useSecurityKey || useKMS {
				// The key pair goes straight into a security-key or KMS file,
				// after an enrollment that asks for touches or calls AWS, in
				// place of the saving step; registering it runs after that.
				run, after = steps[:1], steps[2:]
			}
			if err := ui.RunPipeline(cmd.Context(), "identity", run); err != nil {
				return err
			}
			if useSecurityKey || useKMS {
				var err error
				if useSecurityKey {
					err = saveWithSecurityKey(cmd.Context(), kp, label, backup, recoveryCode, single)
				} else {
					err = saveWithKMS(cmd.Context(), kp, kmsARNs, label, account, recoveryCode, single)
				}
				if err != nil {
					return err
				}
				if len(after) > 0 {
					if err := ui.RunPipeline(cmd.Context(), "identity", after); err != nil {
						return err
					}
				}
			}

			if noPassword {
				ui.Warning("The private keys are stored in clear: anyone who can read the key file can open every secret sent to this identity", "")
			}
			fmt.Fprintln(os.Stderr)
			if number, err := identity.SafetyNumber(fp); err == nil {
				ui.KeyValue("Safety number", number)
			}
			ui.KeyValue("Key fingerprint", fp)
			ui.KeyValue("Ed25519", kp.ED25519Public)
			ui.KeyValue("X25519", kp.X25519Public)
			ui.KeyValue("ML-KEM-768", ui.Abbrev(kp.MLKEM768PK, 16, 8))
			ui.KeyValue("ML-DSA-65", ui.Abbrev(kp.MLDSA65PK, 16, 8))
			ui.KeyValue("Stored at", console.Safe(filepath.Join(config.KeysDir(), fp+".json")))
			if usePassword {
				ui.KeyValue("Encrypted", "yes, with your password")
			}
			if noPassword {
				ui.KeyValue("Encrypted", "no, stored in clear")
			}
			if useSecurityKey {
				ui.KeyValue("Protected", "yes, by your security key")
			}
			if useKMS {
				ui.KeyValue("Protected", "yes, by AWS KMS")
			}
			if !local {
				ui.KeyValue("Registered", "yes, as your primary key"+registeredAs(fp))
			}
			fmt.Fprintln(os.Stderr)
			if local {
				ui.Dimmed("Register its public keys and make it your primary key with:")
				ui.Dimmed("  secret identity sync -i " + fp)
				fmt.Fprintln(os.Stderr)
			}
			if useKMS {
				printKMSPolicy(fp, account)
				ui.Dimmed("Copy the key file to that machine: secret identity import --stdin < " + console.Safe(filepath.Join(config.KeysDir(), fp+".json")))
				fmt.Fprintln(os.Stderr)
			}
			return nil
		},
	}

	cmd.Flags().BoolVarP(&usePassword, "password", "p", false, "Encrypt the private keys with a password (the default)")
	cmd.Flags().BoolVar(&noPassword, "no-password", false, "Store the private keys in clear")
	cmd.Flags().BoolVar(&local, "local", false, "Keep the key pair on this device only, without registering it (by default it is registered and becomes your primary key)")
	cmd.Flags().BoolVar(&useSecurityKey, "security-key", false, "Protect the private keys with a security key such as a YubiKey, in place of a password")
	cmd.Flags().StringArrayVar(&kmsARNs, "kms-arn", nil, "Protect the private keys with the AWS KMS key of this full `ARN` (arn:aws:kms:<region>:<account>:key/<id>), for automation: repeat for a second key, up to 4")
	cmd.Flags().StringVar(&label, "label", "", "With --security-key or --kms-arn: a name for the (first) key")
	cmd.Flags().BoolVar(&backup, "backup", false, "With --security-key: also enroll a backup security key")
	cmd.Flags().BoolVar(&recoveryCode, "recovery-code", false, "With --security-key or --kms-arn: also create a printed recovery code")
	cmd.Flags().BoolVar(&single, "single", false, "With --security-key or --kms-arn: allow one key with no backup and no recovery code")
	flags.SetGroup(cmd.Flags(), flags.GroupOptions, "password", "no-password", "local", "security-key", "kms-arn", "label", "backup", "recovery-code", "single")
	return cmd
}

// checkProtectionPolicy refuses, before a key pair is generated, one that
// the account's organization would refuse to register: an organization
// that requires protected keys takes only a key pair protected by a
// password, a security key or an AWS KMS key. protected says whether the
// key pair about to be generated will be; a protected one needs no request.
func checkProtectionPolicy(ctx context.Context, c *deepsecret.Client, protected bool) error {
	if protected {
		return nil
	}
	required, err := c.Identity.KeyProtectionRequired(ctx)
	if err != nil {
		return fmt.Errorf("could not reach your account to register the key pair: %w", errs.APICause(err))
	}
	if !required {
		return nil
	}
	return errs.WithDetail(sdkidentity.ErrKeyProtectionRequired, "Generate a protected one with one of:\n"+
		"  secret identity generate --password\n"+
		"  secret identity generate --security-key --recovery-code\n"+
		"  secret identity generate --kms-arn <KMS key ARN> --recovery-code")
}

// registerKeyPair signs the public keys of kp, whose fingerprint is fp,
// and registers them on the server, as a step does, labelled with how its
// key file on this device is protected. An organization that requires
// protected keys refuses one that is not, and the error says how to
// protect it and register it again.
func registerKeyPair(ctx context.Context, c *deepsecret.Client, kp *keys.Pair, fp string) (string, error) {
	protection := identity.Protection(fp)
	if err := c.Identity.Sync(ctx, kp, protection); err != nil {
		if errors.Is(err, sdkidentity.ErrKeyProtectionRequired) {
			short := keys.ShortFingerprint(fp)
			return "", errs.WithDetail(err, "Protect it on this device, then register it:\n"+
				"  secret identity security-key protect -i "+short+"\n"+
				"  secret identity kms protect -i "+short+" --kms-arn <KMS key ARN>\n"+
				"  secret identity sync -i "+short)
		}
		return "", fmt.Errorf("could not upload the public keys: %w", errs.APICause(err))
	}
	logging.Module(logging.Log, "identity").Info("key registered", "fingerprint", fp, "protection", string(protection))
	return "fingerprint=" + keys.ShortFingerprint(fp), nil
}

// registeredAs is ", labelled as protected by ..." for the key pair fp,
// for the lines that say it was registered, or "" when its key file
// cannot be read.
func registeredAs(fp string) string {
	if l := identity.LabelPhrase(identity.Protection(fp)); l != "" {
		return ", " + l
	}
	return ""
}

// setPrimaryStep makes the registered key whose fingerprint is *fp the
// primary key. fp is read when the step runs, once the steps before it
// set it.
func setPrimaryStep(ctx context.Context, c *deepsecret.Client, fp *string) ui.Step {
	return ui.Step{
		Label: "Setting it as your primary key",
		Done:  "Primary key set",
		Action: func() (string, error) {
			keyList, err := c.Identity.ListKeys(ctx)
			if err != nil {
				return "", fmt.Errorf("could not list your registered keys: %w", errs.APICause(err))
			}
			k := identity.Registered(keyList, *fp)
			if k == nil {
				return "", fmt.Errorf("the server does not list key %s, uploaded just before", keys.ShortFingerprint(*fp))
			}
			if err := c.Identity.SetPrimaryKey(ctx, k.ID); err != nil {
				return "", fmt.Errorf("could not set the primary key: %w", errs.APICause(err))
			}
			logging.Module(logging.Log, "identity").Info("primary key set", "fingerprint", *fp, "key_id", k.ID)
			return "fingerprint=" + keys.ShortFingerprint(*fp), nil
		},
	}
}

func newIdentityListCmd() *cobra.Command {
	var remote bool

	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List the key pairs on this device (alias: ls)",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if remote {
				return listRemoteKeys(cmd.Context())
			}
			return listLocalKeys(cmd.Context())
		},
	}

	cmd.Flags().BoolVar(&remote, "remote", false, "List the keys registered on the server instead")
	flags.SetGroup(cmd.Flags(), flags.GroupOptions, "remote")
	return cmd
}

func listLocalKeys(ctx context.Context) error {
	names, err := identity.List()
	if err != nil {
		return fmt.Errorf("could not list the key pairs on this device: %w", err)
	}
	if len(names) == 0 {
		ui.Dimmed("No key pairs on this device. Create one with: secret identity generate")
		return nil
	}

	// The server says which key pairs are registered, and which is the
	// primary key. Without it the list shows only what this device knows.
	remote, remoteErr := identity.FetchRegistered(ctx)
	type row struct {
		fp   string
		tags []string
	}
	var rows []row
	var unreadable []string
	for _, n := range names {
		_, fp, err := identity.ReadPublicKeys(n)
		if err != nil {
			unreadable = append(unreadable, fmt.Sprintf("%s.json: %v", console.Safe(n), err))
			continue
		}
		tags := keyTags(identity.Protection(n), identity.Registered(remote, fp), remoteErr == nil)
		rows = append(rows, row{fp, tags})
	}
	logging.Module(logging.Log, "identity").Debug("key pairs listed", "local", len(rows), "unreadable", len(unreadable), "registered", len(remote))

	ui.Header(fmt.Sprintf("Key pairs (%d)", len(rows)))
	fmt.Fprintln(os.Stderr)
	for _, r := range rows {
		suffix := ""
		if len(r.tags) > 0 {
			suffix = " [" + strings.Join(r.tags, ", ") + "]"
		}
		fmt.Printf("  %s%s\n", console.Safe(r.fp), suffix)
	}
	if len(unreadable) == 0 && remoteErr == nil {
		fmt.Fprintln(os.Stderr)
	}
	if len(unreadable) > 0 {
		ui.Warning(fmt.Sprintf("%d key file%s could not be read", len(unreadable), ui.Plural(len(unreadable))), strings.Join(unreadable, "\n"))
	}
	if remoteErr != nil {
		summary, detail := describeFailure(ctx, remoteErr)
		ui.Warning("Could not check which key pairs are registered", strings.TrimSpace(summary+"\n\n"+detail))
	}
	return nil
}

// keyTags are the tags of a key pair in identity list: security-key,
// encrypted, and whether it is registered, as registered (nil when it is
// not), and the primary key. checked says the server was asked; without it,
// whether the key pair is registered is not known.
func keyTags(protection keystore.Protection, registered *sdkidentity.Key, checked bool) []string {
	var tags []string
	if t := identity.ProtectionTag(protection); t != "" {
		tags = append(tags, t)
	}
	switch {
	case !checked:
	case registered == nil:
		tags = append(tags, "local-only")
	case registered.IsPrimary:
		tags = append(tags, "primary", "registered")
	default:
		tags = append(tags, "registered")
	}
	return tags
}

func listRemoteKeys(ctx context.Context) error {
	keyList, err := identity.FetchRegistered(ctx)
	if err != nil {
		return err
	}
	logging.Module(logging.Log, "identity").Debug("registered keys listed", "count", len(keyList))

	if len(keyList) == 0 {
		ui.Dimmed("No keys are registered. Register one with: secret identity sync")
		return nil
	}

	ui.Header(fmt.Sprintf("Registered keys (%d)", len(keyList)))
	fmt.Fprintln(os.Stderr)
	for _, k := range keyList {
		var tags []string
		if k.IsPrimary {
			tags = append(tags, "primary")
		}
		if l := identity.RemoteLabel(k); l != "" {
			tags = append(tags, l)
		}
		label := ""
		if len(tags) > 0 {
			label = " [" + strings.Join(tags, ", ") + "]"
		}
		fmt.Printf("  %s%s  type=%s\n", console.Safe(k.Fingerprint), label, console.Safe(k.IdentityType))
	}
	fmt.Fprintln(os.Stderr)
	return nil
}

func newIdentitySyncCmd() *cobra.Command {
	var identityFP string

	cmd := &cobra.Command{
		Use:     "sync",
		Aliases: []string{"push"},
		Short:   "Register a key pair's public keys and make it your primary key, or, for a registered key, record this account as yours on this device and refresh its protection label (alias: push)",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := auth.NewAuthenticatedClient()
			if err != nil {
				return err
			}

			var remote []sdkidentity.Key
			if err := ui.RunPipeline(cmd.Context(), "identity", []ui.Step{registeredKeysStep(listRemoteKeysOf(cmd.Context(), c), &remote)}); err != nil {
				return err
			}

			// Picked and loaded between the steps: loading an encrypted key
			// pair asks for its password.
			name, err := keyToSync(identityFP, remote)
			if err != nil {
				return err
			}
			// A registered key is not uploaded again, nor unlocked: the
			// account is recorded as yours with it, and its protection
			// label is brought up to date.
			if k := identity.Registered(remote, name); k != nil {
				return syncRegisteredKey(cmd.Context(), c, k, name)
			}
			kp, err := identity.LoadKeyPair(cmd.Context(), name)
			if err != nil {
				return fmt.Errorf("could not load key pair %s: %w", keys.ShortFingerprint(name), err)
			}
			fp, err := keys.Fingerprint(kp)
			if err != nil {
				return fmt.Errorf("could not compute the fingerprint of key pair %s: %w", keys.ShortFingerprint(name), err)
			}
			if identity.Registered(remote, fp) != nil {
				return errs.WithDetail(fmt.Errorf("key pair %s is already registered", keys.ShortFingerprint(fp)),
					"To make it your primary key: secret identity set-primary "+fp)
			}

			steps := []ui.Step{
				{
					Label: "Signing and uploading the public keys",
					Done:  "Public keys uploaded",
					Action: func() (string, error) {
						return registerKeyPair(cmd.Context(), c, kp, fp)
					},
				},
				setPrimaryStep(cmd.Context(), c, &fp),
			}
			if err := ui.RunPipeline(cmd.Context(), "identity", steps); err != nil {
				return err
			}

			ui.Success(fmt.Sprintf("Key %s is registered and is now your primary key%s.", fp, registeredAs(fp)))
			return nil
		},
	}

	cmd.Flags().VarP(flags.NewFingerprint(&identityFP), "identity", "i", "Key pair `fingerprint`, or a prefix of 16+ characters (default: the one not registered yet)")
	flags.SetGroup(cmd.Flags(), flags.GroupIdentity, "identity")
	return cmd
}

// syncRegisteredKey records the account signed in as one of the user's own
// on this device, used with the key pair name, which k says is registered for
// it already (as from another device), then brings k's protection label up
// to date. Nothing is uploaded or unlocked. A secret this device refused as
// from an account it does not know as the user's opens once that account is
// recorded with the key that signed it.
func syncRegisteredKey(ctx context.Context, c *deepsecret.Client, k *sdkidentity.Key, name string) error {
	if err := c.Identity.RecordOwnAccount(ctx, name); err != nil {
		return fmt.Errorf("could not record this account as yours on this device: %w", errs.APICause(err))
	}
	logging.Module(logging.Log, "identity").Info("own account recorded", "fingerprint", name)
	return refreshProtectionLabel(ctx, c, k, name)
}

// keyToSync picks the key pair identity sync registers: the one
// --identity names, else the only one on this device that remote, the
// registered keys, does not list.
func keyToSync(identityFP string, remote []sdkidentity.Key) (string, error) {
	if identityFP != "" {
		return identity.ResolveName(identityFP)
	}
	local, err := identity.List()
	if err != nil {
		return "", fmt.Errorf("could not list the key pairs on this device: %w", err)
	}
	var unregistered []string
	for _, name := range local {
		if identity.Registered(remote, name) == nil {
			unregistered = append(unregistered, name)
		}
	}
	switch {
	case len(unregistered) == 1:
		return unregistered[0], nil
	case len(unregistered) > 1:
		names := make([]string, len(unregistered))
		for i, n := range unregistered {
			names[i] = console.Safe(n)
		}
		return "", errs.WithDetail(fmt.Errorf("%d key pairs on this device are not registered", len(unregistered)),
			"Choose one with -i:\n  "+strings.Join(names, "\n  "))
	case len(local) == 0:
		return "", errs.WithDetail(errors.New("there is no key pair on this device"),
			"Create one and register it with: secret identity generate")
	}
	return "", errs.WithDetail(errors.New("every key pair on this device is already registered"),
		"To make one your primary key: secret identity set-primary <fingerprint>")
}

func newIdentityShowCmd() *cobra.Command {
	var identityFP string

	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show the public keys of a key pair on this device",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			name, primary, err := keyToShow(cmd.Context(), identityFP)
			if err != nil {
				return err
			}
			kp, fp, err := identity.ReadPublicKeys(name)
			if err != nil {
				return fmt.Errorf("could not read key pair %s: %w", keys.ShortFingerprint(name), err)
			}

			var notes []string
			if t := identity.ProtectionTag(identity.Protection(name)); t != "" {
				notes = append(notes, t)
			}
			if primary {
				notes = append(notes, "primary")
			}
			title := "Key pair " + keys.ShortFingerprint(fp)
			if len(notes) > 0 {
				title += " (" + strings.Join(notes, ", ") + ")"
			}
			ui.Header(title)
			fmt.Fprintln(os.Stderr)
			if number, err := identity.SafetyNumber(fp); err == nil {
				ui.KeyValue("Safety number", number)
			}
			ui.KeyValues("Key fingerprint", fingerprint.Group(fp))
			ui.KeyValue("Ed25519", console.Safe(kp.ED25519Public))
			ui.KeyValue("X25519", console.Safe(kp.X25519Public))
			ui.KeyValue("ML-KEM-768", ui.Abbrev(kp.MLKEM768PK, 32, 16))
			ui.KeyValue("ML-DSA-65", ui.Abbrev(kp.MLDSA65PK, 32, 16))
			ui.KeyValue("Algorithm", "X25519 + ML-KEM-768 + AES-256-GCM + Ed25519 + ML-DSA-65")
			fmt.Fprintln(os.Stderr)
			return nil
		},
	}

	cmd.Flags().VarP(flags.NewFingerprint(&identityFP), "identity", "i", "Key pair `fingerprint`, or a prefix of 16+ characters (default: the only one, or your primary key)")
	flags.SetGroup(cmd.Flags(), flags.GroupIdentity, "identity")
	return cmd
}

// keyToShow picks the key pair identity show shows: the one --identity
// names; else the only one on this device; else, of several, the primary
// key, which others send to and compare, when this device holds it.
// primary says it is the primary key.
func keyToShow(ctx context.Context, identityFP string) (name string, primary bool, err error) {
	if identityFP != "" {
		name, err := identity.ResolveName(identityFP)
		return name, false, err
	}
	names, err := identity.List()
	if err != nil {
		return "", false, fmt.Errorf("could not list the key pairs on this device: %w", err)
	}
	switch len(names) {
	case 0:
		return "", false, errs.WithDetail(errors.New("there is no key pair on this device"), "Create one with: secret identity generate")
	case 1:
		return names[0], false, nil
	}
	if name := identity.PrimaryLocal(ctx, names); name != "" {
		return name, true, nil
	}
	ui.Warning(fmt.Sprintf("Showing key pair %s, the first of %d", console.Safe(keys.ShortFingerprint(names[0])), len(names)),
		"None of the key pairs on this device is known to be your primary key. Choose one with -i; list them with: secret identity list")
	return names[0], false, nil
}

func newIdentitySetPrimaryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set-primary <fingerprint>",
		Short: "Make a registered key your primary key",
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.ExactArgs(1)(cmd, args); err != nil {
				return err
			}
			fp, err := fingerprint.Check(args[0])
			if err != nil {
				return fmt.Errorf("invalid fingerprint %q: %w", args[0], err)
			}
			args[0] = fp
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			prefix := args[0]

			c, err := auth.NewAuthenticatedClient()
			if err != nil {
				return err
			}

			var target sdkidentity.Key
			steps := []ui.Step{
				{
					Label: "Fetching your registered keys",
					Done:  "Registered keys fetched",
					Action: func() (string, error) {
						keyList, err := c.Identity.ListKeys(cmd.Context())
						if err != nil {
							return "", fmt.Errorf("could not list your registered keys: %w", errs.APICause(err))
						}
						var matches []sdkidentity.Key
						for _, k := range keyList {
							if strings.HasPrefix(strings.ToLower(k.Fingerprint), prefix) {
								matches = append(matches, k)
							}
						}
						switch {
						case len(keyList) == 0:
							return "", errs.WithDetail(errors.New("no keys are registered"), "Register one with: secret identity sync")
						case len(matches) == 0:
							return "", errs.WithDetail(fmt.Errorf("no registered key matches %s", prefix), "List them with: secret identity list --remote")
						case len(matches) > 1:
							return "", errs.WithDetail(fmt.Errorf("%s matches %d registered keys", prefix, len(matches)), "Give more of the fingerprint.")
						}
						target = matches[0]
						return fmt.Sprintf("keys=%d", len(keyList)), nil
					},
				},
				{
					Label: "Setting your primary key",
					Done:  "Primary key set",
					Action: func() (string, error) {
						if err := c.Identity.SetPrimaryKey(cmd.Context(), target.ID); err != nil {
							return "", fmt.Errorf("could not set the primary key: %w", errs.APICause(err))
						}
						logging.Module(logging.Log, "identity").Info("primary key set", "fingerprint", target.Fingerprint, "key_id", target.ID)
						return "fingerprint=" + keys.ShortFingerprint(target.Fingerprint), nil
					},
				},
			}

			if err := ui.RunPipeline(cmd.Context(), "identity", steps); err != nil {
				return err
			}

			ui.Success(fmt.Sprintf("Key %s is now your primary key.", console.Safe(target.Fingerprint)))
			return nil
		},
	}

	return cmd
}
