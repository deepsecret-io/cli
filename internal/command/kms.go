// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	deepsecret "github.com/deepsecret-io/deepsecret-go"
	"github.com/deepsecret-io/deepsecret-go/awskms"
	"github.com/deepsecret-io/deepsecret-go/keys"
	"github.com/deepsecret-io/deepsecret-go/keystore"
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

// maxKMSKeys is how many KMS keys a key file holds at most.
const maxKMSKeys = 4

// kmsAccount is the DeepSecret account the session acts as: a KMS slot
// binds the key pair to it, in the encryption context every key policy
// checks. It is asked of the server before any AWS call.
func kmsAccount(ctx context.Context) (*deepsecret.Client, string, error) {
	c, err := auth.NewAuthenticatedClient()
	if err != nil {
		return nil, "", errs.WithDetail(err, strings.TrimSpace(errs.JoinDetail("", err)+
			"\n\nAWS KMS protection binds the key pair to your DeepSecret account: sign in (secret login), or give the API key of the account it is for."))
	}
	id, err := c.Identity.ResolveActorID(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("could not reach your account to bind the key pair to it: %w", errs.APICause(err))
	}
	return c, id, nil
}

// checkKMSARNs refuses, before any AWS call, --kms-arn values that are not
// full KMS key ARNs, a repeated one, or none.
func checkKMSARNs(arns []string) error {
	if len(arns) == 0 {
		return errors.New("--kms-arn is needed")
	}
	for i, arn := range arns {
		if !keystore.ValidKMSKeyARN(arn) {
			return errs.WithDetail(fmt.Errorf("--kms-arn %q is not a KMS key ARN", console.Safe(arn)),
				"Give the key's full ARN: arn:aws:kms:<region>:<account>:key/<key id>. A key id or an alias is refused,\n"+
					"since anyone with kms:UpdateAlias can re-point an alias. Find the ARN with:\n"+
					"  aws kms describe-key --key-id alias/<name> --query KeyMetadata.Arn --output text")
		}
		if slices.Contains(arns[:i], arn) {
			return fmt.Errorf("--kms-arn %s is given twice", arn)
		}
	}
	return nil
}

// checkKMSLabel refuses a bad --label before anything is unlocked or AWS
// is called.
func checkKMSLabel(label string) error {
	if label == "" {
		return nil
	}
	if err := keystore.ValidateSlotLabel(label); err != nil {
		return fmt.Errorf("--label: %w", err)
	}
	return nil
}

// checkKMSWays refuses, before any AWS call, flags that give no valid KMS
// key ARN, too many, or no second way in without the waiver.
func checkKMSWays(arns []string, recovery, single bool) error {
	if err := checkKMSARNs(arns); err != nil {
		return err
	}
	switch {
	case len(arns) > maxKMSKeys:
		return fmt.Errorf("a key pair takes at most %d KMS keys", maxKMSKeys)
	case len(arns) > 1 || recovery || single:
		return nil
	}
	return errs.WithDetail(errors.New("an AWS KMS key needs a second way in, or an explicit --single"),
		"Give a second --kms-arn (in another region or AWS account), or --recovery-code for a printed code kept offline.\n"+
			"With --single the key pair cannot be opened if the KMS key is disabled, deleted or out of reach.")
}

// requireCodeTerminal refuses, before anything changes, to make a recovery
// code with no terminal to show it on.
func requireCodeTerminal() error {
	t, err := prompt.OpenTerminal()
	if err != nil {
		return errs.WithDetail(errors.New("a recovery code is shown only on a terminal"),
			"Run the command in a terminal, or use --single or a second --kms-arn where there is none.")
	}
	return t.Close()
}

// addKMSKeys shows each KMS key (its ARN, AWS account and description) and
// adds it to e as a slot bound to account. label names the first key; the
// others get one naming the key and its region.
func addKMSKeys(ctx context.Context, e *keystore.SlotEditor, k *awskms.Client, arns []string, label, account string) error {
	callerAcct := ""
	if caller, err := k.CallerARN(ctx, keystore.KMSKeyRegion(arns[0])); err == nil {
		ui.KeyValue("AWS identity", console.Safe(caller))
		callerAcct = arnAccount(caller)
	}
	for i, arn := range arns {
		key, err := keystore.DescribeKMSKey(ctx, k, arn)
		if err != nil {
			return fmt.Errorf("KMS key %s: %w", console.Safe(arn), err)
		}
		acct := arnAccount(key.ARN)
		where := "AWS account " + acct
		if callerAcct != "" && acct != callerAcct {
			where += ", not yours (" + callerAcct + ")"
		}
		ui.KeyValue("KMS key", console.Safe(key.ARN)+" ("+where+")")
		if key.Description != "" {
			ui.KeyValue("Description", console.Safe(key.Description))
		}
		l := ""
		if i == 0 {
			l = label
		}
		slot, err := e.AddKMS(ctx, k, key.ARN, account, l)
		if err != nil {
			return fmt.Errorf("could not protect the key pair with KMS key %s: %w", console.Safe(key.ARN), err)
		}
		ui.Success("Added " + console.Safe(slot.Label))
	}
	return nil
}

// arnAccount is the AWS account of an ARN, or "".
func arnAccount(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) < 6 {
		return ""
	}
	return parts[4]
}

// kmsDetail is what to do about an AWS KMS failure, for its Error block,
// whichever command met it; "" for any other error.
func kmsDetail(err error) string {
	switch {
	case errors.Is(err, keystore.ErrKMSCredentialsRejected):
		return "AWS rejected the credentials of " + awsCredentialSource() + ".\n" +
			"They may be deactivated, deleted or expired. Choose other credentials with --aws-profile <name>\n" +
			"or AWS_PROFILE=<name>, and check them with: aws sts get-caller-identity --profile <name>"
	case errors.Is(err, keystore.ErrKMSNoCredentials):
		return "No AWS credentials were found in " + awsCredentialSource() + ".\n" +
			"Give a profile with --aws-profile <name> or AWS_PROFILE=<name>, sign in with aws sso login,\n" +
			"or run where a role provides them (GitHub Actions OIDC, an instance or task role)."
	case errors.Is(err, keystore.ErrKMSAccessDenied):
		return "AWS knows this identity, but the KMS key policy or its IAM policy does not allow the call,\n" +
			"with the key pair's encryption context. secret identity kms list shows the values."
	case errors.Is(err, keystore.ErrKMSKeyUnavailable):
		return "A disabled key is enabled again with: aws kms enable-key\n" +
			"A key pending deletion is kept with: aws kms cancel-key-deletion"
	case errors.Is(err, keystore.ErrKMSNotKeyARN):
		return ""
	case errors.Is(err, keystore.ErrKMSKeyRejected):
		return "A key file needs a customer managed, enabled, symmetric encryption key (SYMMETRIC_DEFAULT)."
	}
	return ""
}

// awsCredentialSource names where the AWS SDK takes credentials from, in
// its own order: --aws-profile; then keys in the environment, when both
// AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are set; then a web identity
// token (AWS_WEB_IDENTITY_TOKEN_FILE, as with EKS IRSA); then the profile
// AWS_PROFILE names or the default one, which falls back to a container or
// instance role.
func awsCredentialSource() string {
	switch {
	case identity.AWSProfile != "":
		return "the profile " + console.Safe(identity.AWSProfile) + " (--aws-profile)"
	case os.Getenv("AWS_ACCESS_KEY_ID") != "" && os.Getenv("AWS_SECRET_ACCESS_KEY") != "":
		return "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in the environment"
	case os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE") != "":
		return "the web identity token in AWS_WEB_IDENTITY_TOKEN_FILE"
	case os.Getenv("AWS_PROFILE") != "":
		return "the profile " + console.Safe(os.Getenv("AWS_PROFILE")) + " (AWS_PROFILE)"
	}
	return "the default profile, or this machine's container or instance role (neither --aws-profile nor AWS_PROFILE is set)"
}

// saveWithKMS writes a new key pair straight to a KMS key file, after adding
// its KMS keys and the second way in: it is never on disk unprotected.
func saveWithKMS(ctx context.Context, kp *keys.Pair, arns []string, label, account string, recovery, single bool) error {
	k, err := identity.KMS(ctx)
	if err != nil {
		return err
	}
	e, err := keystore.NewKMSKeyFile(config.KeysDir(), kp)
	if err != nil {
		return fmt.Errorf("could not save the key pair: %w", err)
	}
	defer e.Close()
	if err := addKMSKeys(ctx, e, k, arns, label, account); err != nil {
		return err
	}
	if recovery {
		code, err := e.SetRecoveryCode()
		if err != nil {
			return err
		}
		if err := showRecoveryCode(ctx, code, true); err != nil {
			return err
		}
	}
	if err := e.Commit(single); err != nil {
		if recovery {
			return notSaved(err)
		}
		return fmt.Errorf("could not save the key pair: %w", err)
	}
	logProtected(e, "generated with AWS KMS")
	return nil
}

// unlockKMSForEdit unlocks a KMS-protected key pair to change its slots:
// through KMS, or with the recovery code.
func unlockKMSForEdit(ctx context.Context, name string, useRecovery bool) (*keystore.SlotEditor, *keystore.KeyFileInfo, error) {
	info, err := keystore.ReadInfo(config.KeysDir(), name)
	if err != nil {
		return nil, nil, fmt.Errorf("could not read key pair %s: %w", keys.ShortFingerprint(name), err)
	}
	if info.Protection != keystore.ProtectionKMS {
		return nil, nil, errs.WithDetail(fmt.Errorf("key pair %s is not protected by AWS KMS", keys.ShortFingerprint(name)),
			"Protect it with: secret identity kms protect -i "+keys.ShortFingerprint(name)+" --kms-arn <KMS key ARN>")
	}
	var u keystore.Unlock
	if useRecovery {
		code, err := prompt.Password(ctx, fmt.Sprintf("Recovery code for key pair %s: ", keys.ShortFingerprint(name)))
		if err != nil {
			return nil, nil, err
		}
		u.RecoveryCode = code
	} else {
		if u.KMS, err = identity.KMS(ctx); err != nil {
			return nil, nil, err
		}
	}
	e, err := keystore.Edit(ctx, config.KeysDir(), name, u)
	if err != nil {
		return nil, nil, fmt.Errorf("could not unlock key pair %s: %w", keys.ShortFingerprint(name), err)
	}
	return e, info, nil
}

// kmsAccountOf is the account a KMS key file's slots are bound to.
func kmsAccountOf(info *keystore.KeyFileInfo) string {
	for _, s := range info.Slots {
		if s.Account != "" {
			return s.Account
		}
	}
	return ""
}

// printKMSPolicy prints the key policy statement that lets a machine unlock
// key pairs of account, and the next step.
func printKMSPolicy(fp, account string) {
	statement := map[string]any{
		"Sid":       "UnlockDeepSecretKeyPairs",
		"Effect":    "Allow",
		"Principal": map[string]any{"AWS": "<ARN of the role that unlocks it>"},
		"Action":    "kms:Decrypt",
		"Resource":  "*",
		"Condition": map[string]any{
			"StringEquals": map[string]string{
				"kms:EncryptionContext:" + keystore.KMSContextKeyPurpose: keystore.KMSContextPurpose,
				"kms:EncryptionContext:" + keystore.KMSContextKeyAccount: account,
			},
			"ForAllValues:StringEquals": map[string]any{
				"kms:EncryptionContextKeys": []string{keystore.KMSContextKeyPurpose, keystore.KMSContextKeyFingerprint, keystore.KMSContextKeyAccount, keystore.KMSContextKeySlot},
			},
		},
	}
	data, _ := json.MarshalIndent(statement, "  ", "  ")
	fmt.Fprintln(os.Stderr)
	ui.Dimmed("To let a machine unlock it, allow its AWS role in the KMS key policy (or its IAM policy):")
	fmt.Fprintln(os.Stderr, "  "+string(data))
	ui.Dimmed("To allow this key pair only, also require " + "kms:EncryptionContext:" + keystore.KMSContextKeyFingerprint + " = " + fp + ".")
	ui.Dimmed("Then check it on that machine: secret identity kms check -i " + keys.ShortFingerprint(fp))
}

func newIdentityKMSCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "kms",
		Short: "Protect a key pair for automation with an AWS KMS key",
		Long: "A key pair protected by AWS KMS opens with no password or prompt, for any AWS identity your KMS key\n" +
			"policy and IAM policies allow, on a machine that has its key file. Every unlock is a KMS Decrypt in\n" +
			"your CloudTrail, and revoking that access stops every copy of the file. It is meant for servers,\n" +
			"CI runners and AI agents with a DeepSecret account of their own. For yourself, a security key is\n" +
			"stronger: secret identity security-key.\n\n" +
			"The private keys never go to AWS: KMS only wraps the key that opens the key file. DeepSecret never\n" +
			"holds your KMS key. AWS credentials come from the AWS default chain, or --aws-profile.",
	}
	cmd.AddCommand(newKMSProtectCmd(), newKMSAddCmd(), newKMSListCmd(), newKMSRemoveCmd(),
		newKMSRecoveryCodeCmd(), newKMSUnprotectCmd(), newKMSCheckCmd())
	return cmd
}

func newKMSProtectCmd() *cobra.Command {
	var identityFP, label string
	var arns []string
	var recovery, single bool
	cmd := &cobra.Command{
		Use:   "protect",
		Short: "Protect a key pair with AWS KMS, in place of its password",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := checkKMSWays(arns, recovery, single); err != nil {
				return err
			}
			if err := checkKMSLabel(label); err != nil {
				return err
			}
			if recovery {
				if err := requireCodeTerminal(); err != nil {
					return err
				}
			}
			name, err := keyToProtect(cmd.Context(), identityFP)
			if err != nil {
				return err
			}
			info, err := keystore.ReadInfo(config.KeysDir(), name)
			if err != nil {
				return fmt.Errorf("could not read key pair %s: %w", keys.ShortFingerprint(name), err)
			}
			switch info.Protection {
			case keystore.ProtectionNone, keystore.ProtectionPassword:
			case keystore.ProtectionKMS:
				return errs.WithDetail(fmt.Errorf("key pair %s is already protected by AWS KMS", keys.ShortFingerprint(name)),
					"Add another KMS key with: secret identity kms add -i "+keys.ShortFingerprint(name)+" --kms-arn <KMS key ARN>")
			case keystore.ProtectionSecurityKey:
				return errs.WithDetail(fmt.Errorf("key pair %s is protected by a security key, so it belongs to a person", keys.ShortFingerprint(name)),
					"Give the automation a key pair of its own: secret identity generate --kms-arn <KMS key ARN> --single")
			default:
				return fmt.Errorf("key pair %s: unknown protection %q", keys.ShortFingerprint(name), info.Protection)
			}
			_, account, err := kmsAccount(cmd.Context())
			if err != nil {
				return err
			}
			var pw string
			if info.Protection == keystore.ProtectionPassword {
				if err := identity.RequirePasswordTerminal(name); err != nil {
					return err
				}
				if pw, err = prompt.Password(cmd.Context(), fmt.Sprintf("Password for key pair %s: ", keys.ShortFingerprint(name))); err != nil {
					return err
				}
			}
			e, err := keystore.Edit(cmd.Context(), config.KeysDir(), name, keystore.Unlock{Password: pw})
			if err != nil {
				return fmt.Errorf("could not unlock key pair %s: %w", keys.ShortFingerprint(name), err)
			}
			defer e.Close()
			k, err := identity.KMS(cmd.Context())
			if err != nil {
				return err
			}
			if err := addKMSKeys(cmd.Context(), e, k, arns, label, account); err != nil {
				return err
			}
			if recovery {
				code, err := e.SetRecoveryCode()
				if err != nil {
					return err
				}
				if err := showRecoveryCode(cmd.Context(), code, true); err != nil {
					return err
				}
			}
			if err := e.Commit(single); err != nil {
				if recovery {
					return notSaved(err)
				}
				return fmt.Errorf("could not save the key pair: %w", err)
			}
			logProtected(e, "protected with AWS KMS")
			ui.Success("Key pair " + keys.ShortFingerprint(name) + " is protected by AWS KMS")
			if info.Protection == keystore.ProtectionPassword {
				ui.Dimmed("Its password no longer opens it. Copies of the key file made before now (backups) still open with the password alone.")
			} else {
				ui.Warning("Copies of the key file made before now are still unprotected",
					"If the key file was ever stored elsewhere (a CI secret, a backup), protecting it now does not undo that:\n"+
						"generate a new key pair instead: secret identity generate --kms-arn <KMS key ARN> --single")
			}
			printKMSPolicy(e.Fingerprint(), account)
			return nil
		},
	}
	cmd.Flags().StringVarP(&identityFP, "identity", "i", "", "The key pair to protect (default: the only one, or your primary key)")
	cmd.Flags().StringArrayVar(&arns, "kms-arn", nil, "The AWS KMS key's full `ARN`, arn:aws:kms:<region>:<account>:key/<id> (repeat for a second key, up to 4)")
	cmd.Flags().StringVar(&label, "label", "", "A name for the (first) KMS key (default: its id and region)")
	cmd.Flags().BoolVar(&recovery, "recovery-code", false, "Also create a printed recovery code, which opens the key pair without AWS")
	cmd.Flags().BoolVar(&single, "single", false, "Allow one KMS key with no second key and no recovery code")
	flags.SetGroup(cmd.Flags(), flags.GroupOptions, "identity", "kms-arn", "label", "recovery-code", "single")
	return cmd
}

func newKMSAddCmd() *cobra.Command {
	var identityFP, label string
	var arns []string
	var useRecovery bool
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add another AWS KMS key, such as one in another region",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := checkKMSARNs(arns); err != nil {
				return err
			}
			if err := checkKMSLabel(label); err != nil {
				return err
			}
			name, err := keyToProtect(cmd.Context(), identityFP)
			if err != nil {
				return err
			}
			e, info, err := unlockKMSForEdit(cmd.Context(), name, useRecovery)
			if err != nil {
				return err
			}
			defer e.Close()
			k, err := identity.KMS(cmd.Context())
			if err != nil {
				return err
			}
			account := kmsAccountOf(info)
			if err := addKMSKeys(cmd.Context(), e, k, arns, label, account); err != nil {
				return err
			}
			if err := e.Commit(true); err != nil {
				return fmt.Errorf("could not save the key pair: %w", err)
			}
			logProtected(e, "KMS key added")
			ui.Success("Key pair " + keys.ShortFingerprint(name) + " now opens with the new KMS key too")
			ui.Dimmed("Copy the new key file to the machines that use it: secret identity import --replace")
			printKMSPolicy(e.Fingerprint(), account)
			return nil
		},
	}
	cmd.Flags().StringVarP(&identityFP, "identity", "i", "", "The key pair (default: the only one, or your primary key)")
	cmd.Flags().StringArrayVar(&arns, "kms-arn", nil, "The full `ARN` of the AWS KMS key to add, arn:aws:kms:<region>:<account>:key/<id>")
	cmd.Flags().StringVar(&label, "label", "", "A name for the KMS key (default: its id and region)")
	cmd.Flags().BoolVar(&useRecovery, "recovery-code", false, "Unlock with the recovery code instead of AWS KMS")
	flags.SetGroup(cmd.Flags(), flags.GroupOptions, "identity", "kms-arn", "label", "recovery-code")
	return cmd
}

func newKMSListCmd() *cobra.Command {
	var identityFP string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List a key pair's KMS keys and encryption context, without unlocking it",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			name, err := keyToProtect(cmd.Context(), identityFP)
			if err != nil {
				return err
			}
			info, err := keystore.ReadInfo(config.KeysDir(), name)
			if err != nil {
				return fmt.Errorf("could not read key pair %s: %w", keys.ShortFingerprint(name), err)
			}
			if info.Protection != keystore.ProtectionKMS {
				return errs.WithDetail(fmt.Errorf("key pair %s is not protected by AWS KMS", keys.ShortFingerprint(name)),
					"See how it is protected with: secret identity security-key list -i "+keys.ShortFingerprint(name))
			}
			ui.Header("Key pair " + keys.ShortFingerprint(info.Fingerprint))
			fmt.Fprintln(os.Stderr)
			ui.KeyValue("Protection", "AWS KMS")
			ui.KeyValue("Account", console.Safe(kmsAccountOf(info)))
			fmt.Fprintln(os.Stderr)
			for _, s := range info.Slots {
				switch s.Type {
				case keystore.SlotAWSKMS:
					fmt.Printf("  %s  KMS key        %s  (added %s)\n      %s\n", console.Safe(s.ID), console.Safe(s.Label), s.CreatedAt.Local().Format(time.DateOnly), console.Safe(s.KMSKeyARN))
				case keystore.SlotRecoveryCode:
					fmt.Printf("  %s  recovery code  %s  (added %s)\n", console.Safe(s.ID), console.Safe(s.Label), s.CreatedAt.Local().Format(time.DateOnly))
				}
			}
			fmt.Fprintln(os.Stderr)
			ui.Dimmed("Encryption context of every unlock (for key policies and CloudTrail):")
			ui.Dimmed("  " + keystore.KMSContextKeyPurpose + " = " + keystore.KMSContextPurpose)
			ui.Dimmed("  " + keystore.KMSContextKeyFingerprint + " = " + info.Fingerprint)
			ui.Dimmed("  " + keystore.KMSContextKeyAccount + " = " + console.Safe(kmsAccountOf(info)))
			ui.Dimmed("  " + keystore.KMSContextKeySlot + " = the slot id")
			fmt.Fprintln(os.Stderr)
			return nil
		},
	}
	cmd.Flags().StringVarP(&identityFP, "identity", "i", "", "The key pair (default: the only one, or your primary key)")
	flags.SetGroup(cmd.Flags(), flags.GroupOptions, "identity")
	return cmd
}

func newKMSRemoveCmd() *cobra.Command {
	var identityFP string
	var useRecovery, single bool
	cmd := &cobra.Command{
		Use:   "remove <slot-id>",
		Short: "Remove a KMS key or the recovery code (ids from: secret identity kms list)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, err := keyToProtect(cmd.Context(), identityFP)
			if err != nil {
				return err
			}
			// The slot must exist before anything is unlocked: a mistyped id
			// costs no KMS call.
			info, err := keystore.ReadInfo(config.KeysDir(), name)
			if err != nil {
				return fmt.Errorf("could not read key pair %s: %w", keys.ShortFingerprint(name), err)
			}
			var target *keystore.SlotInfo
			for i := range info.Slots {
				if info.Slots[i].ID == args[0] {
					target = &info.Slots[i]
				}
			}
			if target == nil {
				return errs.WithDetail(fmt.Errorf("key pair %s has no slot %s", keys.ShortFingerprint(name), console.Safe(args[0])),
					"List them with: secret identity kms list -i "+keys.ShortFingerprint(name))
			}
			e, _, err := unlockKMSForEdit(cmd.Context(), name, useRecovery)
			if err != nil {
				return err
			}
			defer e.Close()
			if err := e.Remove(target.ID); err != nil {
				return err
			}
			if err := e.Commit(single); err != nil {
				if errors.Is(err, keystore.ErrSlotRules) {
					return errs.WithDetail(fmt.Errorf("could not save the key pair: %w", err),
						"To take AWS KMS protection off entirely: secret identity kms unprotect")
				}
				return fmt.Errorf("could not save the key pair: %w", err)
			}
			logProtected(e, "slot removed")
			ui.Success("Removed " + console.Safe(target.Label) + " from key pair " + keys.ShortFingerprint(name))
			if target.Type == keystore.SlotAWSKMS {
				ui.Dimmed("Copies of the key file made before now still open with that KMS key while its policies allow it.")
				ui.Dimmed("To stop them, revoke the access in AWS (the key policy, the IAM policy or a grant).")
			} else {
				ui.Dimmed("Copies of the key file made before now still open with that recovery code.")
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&identityFP, "identity", "i", "", "The key pair (default: the only one, or your primary key)")
	cmd.Flags().BoolVar(&useRecovery, "recovery-code", false, "Unlock with the recovery code instead of AWS KMS")
	cmd.Flags().BoolVar(&single, "single", false, "Allow leaving one KMS key with no second key and no recovery code")
	flags.SetGroup(cmd.Flags(), flags.GroupOptions, "identity", "recovery-code", "single")
	return cmd
}

func newKMSRecoveryCodeCmd() *cobra.Command {
	var identityFP string
	var useRecovery bool
	cmd := &cobra.Command{
		Use:   "recovery-code",
		Short: "Create a recovery code, replacing the current one",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireCodeTerminal(); err != nil {
				return err
			}
			name, err := keyToProtect(cmd.Context(), identityFP)
			if err != nil {
				return err
			}
			e, _, err := unlockKMSForEdit(cmd.Context(), name, useRecovery)
			if err != nil {
				return err
			}
			defer e.Close()
			code, err := e.SetRecoveryCode()
			if err != nil {
				return err
			}
			if err := showRecoveryCode(cmd.Context(), code, true); err != nil {
				return err
			}
			if err := e.Commit(false); err != nil {
				return notSaved(err)
			}
			logProtected(e, "recovery code set")
			ui.Success("New recovery code saved for key pair " + keys.ShortFingerprint(name) + "; the old one no longer opens it")
			ui.Dimmed("Copies of the key file made before now still open with the old code.")
			return nil
		},
	}
	cmd.Flags().StringVarP(&identityFP, "identity", "i", "", "The key pair (default: the only one, or your primary key)")
	cmd.Flags().BoolVar(&useRecovery, "recovery-code", false, "Unlock with the current recovery code instead of AWS KMS")
	flags.SetGroup(cmd.Flags(), flags.GroupOptions, "identity", "recovery-code")
	return cmd
}

func newKMSUnprotectCmd() *cobra.Command {
	var identityFP string
	var useRecovery, noPassword bool
	cmd := &cobra.Command{
		Use:   "unprotect",
		Short: "Take AWS KMS protection off, back to a password",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			name, err := keyToProtect(cmd.Context(), identityFP)
			if err != nil {
				return err
			}
			if !noPassword {
				t, err := prompt.OpenTerminal()
				if err != nil {
					return errs.WithDetail(errors.New("the new password is typed on a terminal"),
						"Run the command in a terminal, or use --no-password to store the key pair unprotected.")
				}
				_ = t.Close()
			}
			e, _, err := unlockKMSForEdit(cmd.Context(), name, useRecovery)
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
			logging.Module(logging.Log, "identity").Info("AWS KMS protection removed", "fingerprint", e.Fingerprint(), "password", !noPassword)
			ui.Success("Key pair " + keys.ShortFingerprint(name) + " no longer opens through AWS KMS")
			ui.Warning("A copy of the key file can be guessed at offline again", "Its KMS keys and recovery code no longer open it; its password does.")
			return nil
		},
	}
	cmd.Flags().StringVarP(&identityFP, "identity", "i", "", "The key pair (default: the only one, or your primary key)")
	cmd.Flags().BoolVar(&useRecovery, "recovery-code", false, "Unlock with the recovery code instead of AWS KMS")
	cmd.Flags().BoolVar(&noPassword, "no-password", false, "Store the private keys in clear")
	flags.SetGroup(cmd.Flags(), flags.GroupOptions, "identity", "recovery-code", "no-password")
	return cmd
}

func newKMSCheckCmd() *cobra.Command {
	var identityFP string
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Unlock a key pair through AWS KMS once, to check this machine can (shows nothing secret)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			name, err := keyToProtect(cmd.Context(), identityFP)
			if err != nil {
				return err
			}
			info, err := keystore.ReadInfo(config.KeysDir(), name)
			if err != nil {
				return fmt.Errorf("could not read key pair %s: %w", keys.ShortFingerprint(name), err)
			}
			if info.Protection != keystore.ProtectionKMS {
				return fmt.Errorf("key pair %s is not protected by AWS KMS", keys.ShortFingerprint(name))
			}
			k, err := identity.KMS(cmd.Context())
			if err != nil {
				return err
			}
			ui.KeyValue("Key pair", info.Fingerprint)
			region := ""
			for _, s := range info.Slots {
				if s.Type == keystore.SlotAWSKMS {
					ui.KeyValue("KMS key", console.Safe(s.KMSKeyARN))
					if region == "" {
						region = keystore.KMSKeyRegion(s.KMSKeyARN)
					}
				}
			}
			if caller, err := k.CallerARN(cmd.Context(), region); err == nil {
				ui.KeyValue("AWS identity", console.Safe(caller))
			}
			if _, err := keystore.Open(cmd.Context(), config.KeysDir(), name, keystore.Unlock{KMS: k}); err != nil {
				return fmt.Errorf("key pair %s does not unlock here: %w", keys.ShortFingerprint(name), err)
			}
			logging.Module(logging.Log, "identity").Info("KMS unlock checked", "fingerprint", info.Fingerprint)
			ui.Success("Key pair " + keys.ShortFingerprint(name) + " unlocks here through AWS KMS")
			return nil
		},
	}
	cmd.Flags().StringVarP(&identityFP, "identity", "i", "", "The key pair (default: the only one, or your primary key)")
	flags.SetGroup(cmd.Flags(), flags.GroupOptions, "identity")
	return cmd
}

// maxImport bounds what secret identity import reads: a key file is far
// smaller.
const maxImport = 1 << 20

func newIdentityImportCmd() *cobra.Command {
	var file string
	var stdin, replace bool
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Place a protected key file made on another machine on this one",
		Long: "Read a key file protected by AWS KMS or a security key, check it, and save it in this device's\n" +
			"keys directory, private to you. An unprotected or password-protected key file is refused.\n\n" +
			"Examples:\n" +
			"  printf '%s' \"$DEEPSECRET_KEY_FILE\" | secret identity import --stdin\n" +
			"  secret identity import --file ./1f2e3d.json",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			var r io.Reader
			switch {
			case stdin == (file != ""):
				return errors.New("give the key file with --file or --stdin")
			case stdin:
				r = os.Stdin
			default:
				f, err := os.Open(file) // #nosec G304 -- the user names the file to read.
				if err != nil {
					return err
				}
				defer func() { _ = f.Close() }()
				r = f
			}
			data, err := io.ReadAll(io.LimitReader(r, maxImport+1))
			if err != nil {
				return err
			}
			fp, err := keystore.Import(config.KeysDir(), data, replace)
			clear(data)
			if errors.Is(err, keystore.ErrKeyFileExists) {
				return errs.WithDetail(err, "To replace it with this file, add --replace.")
			}
			if err != nil {
				return fmt.Errorf("could not import the key file: %w", err)
			}
			logging.Module(logging.Log, "identity").Info("key file imported", "fingerprint", fp, "replace", replace)
			ui.Success("Key pair " + keys.ShortFingerprint(fp) + identity.ProtectionNote(fp) + " is on this device")
			return nil
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "Read the key file from `path`")
	cmd.Flags().BoolVar(&stdin, "stdin", false, "Read the key file from stdin")
	cmd.Flags().BoolVar(&replace, "replace", false, "Replace a different key file already here for the same key pair")
	flags.SetGroup(cmd.Flags(), flags.GroupOptions, "file", "stdin", "replace")
	return cmd
}
