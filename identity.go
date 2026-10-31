// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/deepsecret-io/sdk"
	"github.com/deepsecret-io/sdk/api"
	"github.com/deepsecret-io/sdk/crypto"
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
	)

	return cmd
}

func newIdentityGenerateCmd() *cobra.Command {
	var usePassword bool
	var syncAfter bool

	cmd := &cobra.Command{
		Use:     "generate",
		Aliases: []string{"gen"},
		Short:   "Generate a new key pair (alias: gen)",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// With --sync, check the login first, so a missing one does not
			// leave a new key pair saved but not registered.
			var c *Client
			if syncAfter {
				var err error
				if c, err = newAuthenticatedClient(); err != nil {
					return err
				}
			}
			var password string
			if usePassword {
				var err error
				password, err = readPasswordConfirm("Set key password: ")
				if err != nil {
					return err
				}
				if password == "" {
					return fmt.Errorf("--password needs a password that is not empty")
				}
			}

			var kp *crypto.KeyPair
			var fp string
			steps := []step{
				{
					label: "Generating a hybrid key pair",
					done:  "Key pair generated",
					action: func() (string, error) {
						var err error
						if kp, err = crypto.GenerateKeyPair(); err != nil {
							return "", fmt.Errorf("could not generate a key pair: %w", err)
						}
						if fp, err = crypto.Fingerprint(kp); err != nil {
							return "", fmt.Errorf("could not compute the key pair's fingerprint: %w", err)
						}
						if existsKeyPair(fp) {
							return "", fmt.Errorf("a key pair with fingerprint %s already exists", fp)
						}
						return "fingerprint=" + crypto.ShortFingerprint(fp), nil
					},
				},
				{
					label: "Saving the key pair",
					done:  "Key pair saved",
					action: func() (string, error) {
						if err := saveKeyPair(fp, kp, password); err != nil {
							return "", fmt.Errorf("could not save the key pair: %w", err)
						}
						api.Module(logger, "identity").Info("key pair generated", "fingerprint", fp, "encrypted", usePassword)
						if usePassword {
							return "encrypted=true", nil
						}
						return "", nil
					},
				},
			}
			if syncAfter {
				steps = append(steps,
					step{
						label: "Signing and uploading the public keys",
						done:  "Public keys uploaded",
						action: func() (string, error) {
							return registerKeyPair(c, kp, fp)
						},
					},
					setPrimaryStep(c, &fp),
				)
			}

			if err := runPipeline("identity", steps); err != nil {
				return err
			}

			fmt.Fprintln(os.Stderr)
			printKeyValue("Fingerprint", fp)
			printKeyValue("Ed25519", kp.ED25519Public)
			printKeyValue("X25519", kp.X25519Public)
			printKeyValue("ML-KEM-768", abbrev(kp.MLKEM768PK, 16, 8))
			printKeyValue("ML-DSA-65", abbrev(kp.MLDSA65PK, 16, 8))
			printKeyValue("Stored at", safe(filepath.Join(keysDir(), fp+".json")))
			if usePassword {
				printKeyValue("Encrypted", "yes, with your password")
			}
			if syncAfter {
				printKeyValue("Registered", "yes, as your primary key")
			}
			fmt.Fprintln(os.Stderr)
			if !syncAfter {
				printDim("Register its public keys and make it your primary key with:")
				printDim("  secret identity sync -i " + fp)
				fmt.Fprintln(os.Stderr)
			}
			return nil
		},
	}

	cmd.Flags().BoolVarP(&usePassword, "password", "p", false, "Encrypt the private keys with a password")
	cmd.Flags().BoolVarP(&syncAfter, "sync", "s", false, "Register the public keys and make the key pair your primary key after generating it")
	setGroup(cmd.Flags(), groupOptions, "password", "sync")
	return cmd
}

// registerKeyPair signs the public keys of kp, whose fingerprint is fp,
// and registers them on the server, as a step does.
func registerKeyPair(c *Client, kp *crypto.KeyPair, fp string) (string, error) {
	if err := c.SyncIdentity(kp); err != nil {
		return "", fmt.Errorf("could not upload the public keys: %w", apiCause(err))
	}
	api.Module(logger, "identity").Info("key registered", "fingerprint", fp)
	return "fingerprint=" + crypto.ShortFingerprint(fp), nil
}

// setPrimaryStep makes the registered key whose fingerprint is *fp the
// primary key. fp is read when the step runs, once the steps before it
// set it.
func setPrimaryStep(c *Client, fp *string) step {
	return step{
		label: "Setting it as your primary key",
		done:  "Primary key set",
		action: func() (string, error) {
			keys, err := c.ListRemoteKeys()
			if err != nil {
				return "", fmt.Errorf("could not list your registered keys: %w", apiCause(err))
			}
			k := registeredKey(keys, *fp)
			if k == nil {
				return "", fmt.Errorf("the server does not list key %s, uploaded just before", crypto.ShortFingerprint(*fp))
			}
			if err := c.SetPrimaryKey(k.ID); err != nil {
				return "", fmt.Errorf("could not set the primary key: %w", apiCause(err))
			}
			api.Module(logger, "identity").Info("primary key set", "fingerprint", *fp, "key_id", k.ID)
			return "fingerprint=" + crypto.ShortFingerprint(*fp), nil
		},
	}
}

// existsKeyPair checks if a key pair file exists on disk.
func existsKeyPair(fingerprint string) bool {
	path, ok := keyFile(fingerprint)
	if !ok {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func newIdentityListCmd() *cobra.Command {
	var remote bool

	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List the key pairs on this device (alias: ls)",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if remote {
				return listRemoteKeys()
			}
			return listLocalKeys()
		},
	}

	cmd.Flags().BoolVar(&remote, "remote", false, "List the keys registered on the server instead")
	setGroup(cmd.Flags(), groupOptions, "remote")
	return cmd
}

func listLocalKeys() error {
	names, err := listKeyPairs()
	if err != nil {
		return fmt.Errorf("could not list the key pairs on this device: %w", err)
	}
	if len(names) == 0 {
		printDim("No key pairs on this device. Create one with: secret identity generate")
		return nil
	}

	// The server says which key pairs are registered, and which is the
	// primary key. Without it the list shows only what this device knows.
	remote, remoteErr := fetchRegisteredKeys()
	type row struct {
		fp   string
		tags []string
	}
	var rows []row
	var unreadable []string
	for _, n := range names {
		_, fp, err := readPublicKeys(n)
		if err != nil {
			unreadable = append(unreadable, fmt.Sprintf("%s.json: %v", safe(n), err))
			continue
		}
		rows = append(rows, row{fp, keyTags(isKeyPairEncrypted(n), registeredKey(remote, fp), remoteErr == nil)})
	}
	api.Module(logger, "identity").Debug("key pairs listed", "local", len(rows), "unreadable", len(unreadable), "registered", len(remote))

	printHeader(fmt.Sprintf("Key pairs (%d)", len(rows)))
	fmt.Fprintln(os.Stderr)
	for _, r := range rows {
		suffix := ""
		if len(r.tags) > 0 {
			suffix = " [" + strings.Join(r.tags, ", ") + "]"
		}
		fmt.Printf("  %s%s\n", safe(r.fp), suffix)
	}
	if len(unreadable) == 0 && remoteErr == nil {
		fmt.Fprintln(os.Stderr)
	}
	if len(unreadable) > 0 {
		printWarning(fmt.Sprintf("%d key file%s could not be read", len(unreadable), pluralS(len(unreadable))), strings.Join(unreadable, "\n"))
	}
	if remoteErr != nil {
		summary, detail := describeError(remoteErr)
		printWarning("Could not check which key pairs are registered", strings.TrimSpace(summary+"\n\n"+detail))
	}
	return nil
}

// keyTags are the tags of a key pair in identity list: encrypted, and
// whether it is registered, as registered (nil when it is not), and the
// primary key. checked says the server was asked; without it, whether the
// key pair is registered is not known.
func keyTags(encrypted bool, registered *sdk.RemoteKey, checked bool) []string {
	var tags []string
	if encrypted {
		tags = append(tags, "encrypted")
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

// fetchRegisteredKeys lists the keys registered for the account.
func fetchRegisteredKeys() ([]sdk.RemoteKey, error) {
	c, err := newAuthenticatedClient()
	if err != nil {
		return nil, err
	}
	keys, err := c.ListRemoteKeys()
	if err != nil {
		return nil, fmt.Errorf("could not list your registered keys: %w", apiCause(err))
	}
	return keys, nil
}

// registeredKey is the key among keys whose fingerprint matches fp, or
// nil.
func registeredKey(keys []sdk.RemoteKey, fp string) *sdk.RemoteKey {
	for i := range keys {
		if fingerprintMatch(keys[i].Fingerprint, fp) {
			return &keys[i]
		}
	}
	return nil
}

func listRemoteKeys() error {
	keys, err := fetchRegisteredKeys()
	if err != nil {
		return err
	}
	api.Module(logger, "identity").Debug("registered keys listed", "count", len(keys))

	if len(keys) == 0 {
		printDim("No keys are registered. Register one with: secret identity sync")
		return nil
	}

	printHeader(fmt.Sprintf("Registered keys (%d)", len(keys)))
	fmt.Fprintln(os.Stderr)
	for _, k := range keys {
		primary := ""
		if k.IsPrimary {
			primary = " [primary]"
		}
		fmt.Printf("  %s%s  type=%s\n", safe(k.Fingerprint), primary, safe(k.IdentityType))
	}
	fmt.Fprintln(os.Stderr)
	return nil
}

func newIdentitySyncCmd() *cobra.Command {
	var identityFP string

	cmd := &cobra.Command{
		Use:     "sync",
		Aliases: []string{"push"},
		Short:   "Register a key pair's public keys and make it your primary key (alias: push)",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newAuthenticatedClient()
			if err != nil {
				return err
			}

			var remote []sdk.RemoteKey
			if err := runPipeline("identity", []step{registeredKeysStep(c.ListRemoteKeys, &remote)}); err != nil {
				return err
			}

			// Picked and loaded between the steps: loading an encrypted key
			// pair asks for its password.
			name, err := keyToSync(identityFP, remote)
			if err != nil {
				return err
			}
			kp, err := loadKeyPair(name)
			if err != nil {
				return fmt.Errorf("could not load key pair %s: %w", crypto.ShortFingerprint(name), err)
			}
			fp, err := crypto.Fingerprint(kp)
			if err != nil {
				return fmt.Errorf("could not compute the fingerprint of key pair %s: %w", crypto.ShortFingerprint(name), err)
			}
			if registeredKey(remote, fp) != nil {
				return withDetail(fmt.Errorf("key pair %s is already registered", crypto.ShortFingerprint(fp)),
					"To make it your primary key: secret identity set-primary "+fp)
			}

			steps := []step{
				{
					label: "Signing and uploading the public keys",
					done:  "Public keys uploaded",
					action: func() (string, error) {
						return registerKeyPair(c, kp, fp)
					},
				},
				setPrimaryStep(c, &fp),
			}
			if err := runPipeline("identity", steps); err != nil {
				return err
			}

			printSuccess(fmt.Sprintf("Key %s is registered and is now your primary key.", fp))
			return nil
		},
	}

	cmd.Flags().VarP(&fingerprintFlag{&identityFP}, "identity", "i", "Key pair `fingerprint`, or a prefix of 16+ characters (default: the one not registered yet)")
	setGroup(cmd.Flags(), groupIdentity, "identity")
	return cmd
}

// keyToSync picks the key pair identity sync registers: the one
// --identity names, else the only one on this device that remote, the
// registered keys, does not list.
func keyToSync(identityFP string, remote []sdk.RemoteKey) (string, error) {
	if identityFP != "" {
		return resolveIdentityName(identityFP)
	}
	local, err := listKeyPairs()
	if err != nil {
		return "", fmt.Errorf("could not list the key pairs on this device: %w", err)
	}
	var unregistered []string
	for _, name := range local {
		if registeredKey(remote, name) == nil {
			unregistered = append(unregistered, name)
		}
	}
	switch {
	case len(unregistered) == 1:
		return unregistered[0], nil
	case len(unregistered) > 1:
		names := make([]string, len(unregistered))
		for i, n := range unregistered {
			names[i] = safe(n)
		}
		return "", withDetail(fmt.Errorf("%d key pairs on this device are not registered", len(unregistered)),
			"Choose one with -i:\n  "+strings.Join(names, "\n  "))
	case len(local) == 0:
		return "", withDetail(errors.New("there is no key pair on this device"),
			"Create one and register it with: secret identity generate --sync")
	}
	return "", withDetail(errors.New("every key pair on this device is already registered"),
		"To make one your primary key: secret identity set-primary <fingerprint>")
}

func newIdentityShowCmd() *cobra.Command {
	var identityFP string

	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show the public keys of a key pair on this device",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			name, primary, err := keyToShow(identityFP)
			if err != nil {
				return err
			}
			kp, fp, err := readPublicKeys(name)
			if err != nil {
				return fmt.Errorf("could not read key pair %s: %w", crypto.ShortFingerprint(name), err)
			}

			var notes []string
			if isKeyPairEncrypted(name) {
				notes = append(notes, "encrypted")
			}
			if primary {
				notes = append(notes, "primary")
			}
			title := "Key pair " + crypto.ShortFingerprint(fp)
			if len(notes) > 0 {
				title += " (" + strings.Join(notes, ", ") + ")"
			}
			printHeader(title)
			fmt.Fprintln(os.Stderr)
			printKeyValues("Fingerprint", groupFingerprint(fp))
			printKeyValue("Ed25519", safe(kp.ED25519Public))
			printKeyValue("X25519", safe(kp.X25519Public))
			printKeyValue("ML-KEM-768", abbrev(kp.MLKEM768PK, 32, 16))
			printKeyValue("ML-DSA-65", abbrev(kp.MLDSA65PK, 32, 16))
			printKeyValue("Algorithm", "X25519 + ML-KEM-768 + AES-256-GCM + Ed25519 + ML-DSA-65")
			fmt.Fprintln(os.Stderr)
			return nil
		},
	}

	cmd.Flags().VarP(&fingerprintFlag{&identityFP}, "identity", "i", "Key pair `fingerprint`, or a prefix of 16+ characters (default: the only one, or your primary key)")
	setGroup(cmd.Flags(), groupIdentity, "identity")
	return cmd
}

// keyToShow picks the key pair identity show shows: the one --identity
// names; else the only one on this device; else, of several, the primary
// key, which others send to and compare, when this device holds it.
// primary says it is the primary key.
func keyToShow(identityFP string) (name string, primary bool, err error) {
	if identityFP != "" {
		name, err := resolveIdentityName(identityFP)
		return name, false, err
	}
	names, err := listKeyPairs()
	if err != nil {
		return "", false, fmt.Errorf("could not list the key pairs on this device: %w", err)
	}
	switch len(names) {
	case 0:
		return "", false, withDetail(errors.New("there is no key pair on this device"), "Create one with: secret identity generate")
	case 1:
		return names[0], false, nil
	}
	if name := primaryLocalKey(names); name != "" {
		return name, true, nil
	}
	printWarning(fmt.Sprintf("Showing key pair %s, the first of %d", safe(crypto.ShortFingerprint(names[0])), len(names)),
		"None of the key pairs on this device is known to be your primary key. Choose one with -i; list them with: secret identity list")
	return names[0], false, nil
}

// primaryLocalKey is the one of names, the key pairs on this device, that
// is the primary key the server lists, or "" when none is or the server
// cannot be asked.
func primaryLocalKey(names []string) string {
	keys, err := fetchRegisteredKeys()
	if err != nil {
		api.Module(logger, "identity").Warn("primary key lookup failed", "error", err)
		return ""
	}
	for _, k := range keys {
		if !k.IsPrimary {
			continue
		}
		for _, n := range names {
			if fingerprintMatch(n, k.Fingerprint) {
				return n
			}
		}
	}
	return ""
}

func newIdentitySetPrimaryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set-primary <fingerprint>",
		Short: "Make a registered key your primary key",
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.ExactArgs(1)(cmd, args); err != nil {
				return err
			}
			fp, err := checkFingerprint(args[0])
			if err != nil {
				return fmt.Errorf("invalid fingerprint %q: %w", args[0], err)
			}
			args[0] = fp
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			prefix := args[0]

			c, err := newAuthenticatedClient()
			if err != nil {
				return err
			}

			var target sdk.RemoteKey
			steps := []step{
				{
					label: "Fetching your registered keys",
					done:  "Registered keys fetched",
					action: func() (string, error) {
						keys, err := c.ListRemoteKeys()
						if err != nil {
							return "", fmt.Errorf("could not list your registered keys: %w", apiCause(err))
						}
						var matches []sdk.RemoteKey
						for _, k := range keys {
							if fingerprintMatch(k.Fingerprint, prefix) {
								matches = append(matches, k)
							}
						}
						switch {
						case len(keys) == 0:
							return "", withDetail(errors.New("no keys are registered"), "Register one with: secret identity sync")
						case len(matches) == 0:
							return "", withDetail(fmt.Errorf("no registered key matches %s", prefix), "List them with: secret identity list --remote")
						case len(matches) > 1:
							return "", withDetail(fmt.Errorf("%s matches %d registered keys", prefix, len(matches)), "Give more of the fingerprint.")
						}
						target = matches[0]
						return fmt.Sprintf("keys=%d", len(keys)), nil
					},
				},
				{
					label: "Setting your primary key",
					done:  "Primary key set",
					action: func() (string, error) {
						if err := c.SetPrimaryKey(target.ID); err != nil {
							return "", fmt.Errorf("could not set the primary key: %w", apiCause(err))
						}
						api.Module(logger, "identity").Info("primary key set", "fingerprint", target.Fingerprint, "key_id", target.ID)
						return "fingerprint=" + crypto.ShortFingerprint(target.Fingerprint), nil
					},
				},
			}

			if err := runPipeline("identity", steps); err != nil {
				return err
			}

			printSuccess(fmt.Sprintf("Key %s is now your primary key.", safe(target.Fingerprint)))
			return nil
		},
	}

	return cmd
}
