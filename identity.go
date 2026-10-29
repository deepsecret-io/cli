// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/deepsecret-io/sdk/crypto"
)

func newIdentityCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "identity",
		Aliases: []string{"id"},
		Short:   "Manage identity keys (alias: id)",
	}

	cmd.AddCommand(
		newIdentityGenerateCmd(),
		newIdentityListCmd(),
		newIdentitySyncCmd(),
		newIdentityShowCmd(),
		newIdentitySetPrimaryCmd(),
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
			var kp *crypto.KeyPair
			var fp string
			var password string

			steps := []step{
				{
					label: "Generating hybrid key pair",
					action: func() (string, error) {
						var err error
						kp, err = crypto.GenerateKeyPair()
						if err != nil {
							return "", fmt.Errorf("key generation failed: %w", err)
						}
						fp, _ = crypto.Fingerprint(kp)
						if existsKeyPair(fp) {
							return "", fmt.Errorf("key pair with fingerprint %s already exists", fp)
						}
						return fmt.Sprintf("fingerprint=%s", fp[:16]), nil
					},
				},
			}

			if usePassword {
				var err error
				password, err = readPasswordConfirm("Set key password: ")
				if err != nil {
					return err
				}
				if password == "" {
					return fmt.Errorf("password cannot be empty when --password is set")
				}
			}

			steps = append(steps, step{
				label: "Saving key pair to disk",
				action: func() (string, error) {
					if err := saveKeyPair(fp, kp, password); err != nil {
						return "", fmt.Errorf("save key pair: %w", err)
					}
					encrypted := ""
					if usePassword {
						encrypted = ", encrypted=true"
					}
					return fmt.Sprintf("path=%s/%s.json%s", keysDir(), fp[:16], encrypted), nil
				},
			})

			if syncAfter {
				steps = append(steps,
					step{
						label: "Signing key bundle",
						action: func() (string, error) {
							_, _, err := crypto.SignKeyBundle(kp)
							if err != nil {
								return "", fmt.Errorf("sign key bundle: %w", err)
							}
							return fmt.Sprintf("algo=Ed25519+ML-DSA-65, fingerprint=%s", fp[:16]), nil
						},
					},
					step{
						label: "Uploading public keys",
						action: func() (string, error) {
							c, err := newAuthenticatedClient()
							if err != nil {
								return "", fmt.Errorf("authentication required for --sync: %w", err)
							}
							if err := c.SyncIdentity(kp); err != nil {
								return "", fmt.Errorf("sync failed: %w", err)
							}
							return fmt.Sprintf("fingerprint=%s", fp[:16]), nil
						},
					},
					step{
						label: "Setting as primary key",
						action: func() (string, error) {
							c, err := newAuthenticatedClient()
							if err != nil {
								return "", err
							}
							keys, err := c.ListRemoteKeys()
							if err != nil {
								return "", fmt.Errorf("fetch keys: %w", err)
							}
							for _, k := range keys {
								if fingerprintMatch(k.Fingerprint, fp) {
									if err := c.SetPrimaryKey(k.ID); err != nil {
										return "", fmt.Errorf("set primary: %w", err)
									}
									return fmt.Sprintf("fingerprint=%s", crypto.ShortFingerprint(fp)), nil
								}
							}
							return fmt.Sprintf("fingerprint=%s", fp[:16]), nil
						},
					},
				)
			}

			if err := runPipeline("Identity Generate", steps, nil); err != nil {
				return err
			}

			fmt.Fprintln(os.Stderr)
			fmt.Fprintf(os.Stderr, "  %s%-14s%s %s\n", ansiDim, "Fingerprint", ansiReset, fp)
			fmt.Fprintf(os.Stderr, "  %s%-14s%s %s\n", ansiDim, "Ed25519", ansiReset, kp.ED25519Public)
			fmt.Fprintf(os.Stderr, "  %s%-14s%s %s\n", ansiDim, "X25519", ansiReset, kp.X25519Public)
			fmt.Fprintf(os.Stderr, "  %s%-14s%s %s\n", ansiDim, "ML-KEM-768", ansiReset, abbrev(kp.MLKEM768PK, 16, 8))
			fmt.Fprintf(os.Stderr, "  %s%-14s%s %s\n", ansiDim, "ML-DSA-65", ansiReset, abbrev(kp.MLDSA65PK, 16, 8))
			fmt.Fprintf(os.Stderr, "  %s%-14s%s %s\n", ansiDim, "Stored at", ansiReset, keysDir()+"/"+fp+".json")
			if usePassword {
				fmt.Fprintf(os.Stderr, "  %s%-14s%s %s\n", ansiDim, "Encrypted", ansiReset, "yes (password-protected)")
			}
			if syncAfter {
				fmt.Fprintf(os.Stderr, "  %s%-14s%s %s\n", ansiDim, "Synced", ansiReset, "yes (set as primary)")
			}
			fmt.Fprintln(os.Stderr)
			if !syncAfter {
				fmt.Fprintf(os.Stderr, "  %s%s%s\n", ansiDim, "Run 'secret identity sync' to upload public keys to the server.", ansiReset)
				fmt.Fprintln(os.Stderr)
			}
			return nil
		},
	}

	cmd.Flags().BoolVarP(&usePassword, "password", "p", false, "Encrypt the private keys with a password")
	cmd.Flags().BoolVarP(&syncAfter, "sync", "s", false, "Upload the public keys and make the key your primary after generating it")
	setGroup(cmd.Flags(), groupOptions, "password", "sync")
	return cmd
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
		Short:   "List identities (alias: ls)",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if remote {
				return listRemoteKeys()
			}
			return listLocalKeys()
		},
	}

	cmd.Flags().BoolVar(&remote, "remote", false, "List the identities synced to the server")
	setGroup(cmd.Flags(), groupOptions, "remote")
	return cmd
}

func listLocalKeys() error {
	start := time.Now()
	names, err := listKeyPairs()
	if err != nil {
		return err
	}
	if len(names) == 0 {
		printDim("No local identities. Run: secret identity generate")
		return nil
	}

	// Fetch remote keys to cross-reference registered + primary status
	remoteKeys := map[string]bool{}
	primaryFP := ""
	if c, cfgErr := newAuthenticatedClient(); cfgErr == nil {
		if keys, err := c.ListRemoteKeys(); err == nil {
			for _, k := range keys {
				remoteKeys[k.Fingerprint] = true
				if k.IsPrimary {
					primaryFP = k.Fingerprint
				}
			}
		}
	}

	logInfo("ds.identity_list", fmt.Sprintf("found %d local identities (%s)", len(names), fmtDuration(time.Since(start))))

	printHeader(fmt.Sprintf("Identities (%d)", len(names)))
	fmt.Println()

	for _, n := range names {
		encrypted := isKeyPairEncrypted(n)
		data, err := os.ReadFile(filepath.Join(keysDir(), n+".json")) // #nosec G304 -- n is a file name listKeyPairs read from the keys directory.
		if err != nil {
			continue
		}
		var raw crypto.KeyPair
		if err := json.Unmarshal(data, &raw); err != nil {
			continue
		}
		fp, _ := crypto.Fingerprint(&raw)

		var tags []string
		if encrypted {
			tags = append(tags, "encrypted")
		}
		if fp == primaryFP {
			tags = append(tags, "primary")
		}
		if remoteKeys[fp] {
			tags = append(tags, "registered")
		} else {
			tags = append(tags, "local-only")
		}

		suffix := ""
		if len(tags) > 0 {
			suffix = " [" + strings.Join(tags, ", ") + "]"
		}
		fmt.Printf("  %s%s\n", safe(fp), suffix)
	}
	fmt.Println()
	return nil
}

func listRemoteKeys() error {
	c, err := newAuthenticatedClient()
	if err != nil {
		return err
	}

	start := time.Now()
	logInfo("ds.identity_list", "fetching remote identities")
	keys, err := c.ListRemoteKeys()
	if err != nil {
		return err
	}

	logInfo("ds.identity_list", fmt.Sprintf("found %d remote identities (%s)", len(keys), fmtDuration(time.Since(start))))

	if len(keys) == 0 {
		printDim("No remote identities. Run: secret identity sync")
		return nil
	}

	printHeader(fmt.Sprintf("Remote identities (%d)", len(keys)))
	fmt.Println()
	for _, k := range keys {
		primary := ""
		if k.IsPrimary {
			primary = " [primary]"
		}
		fmt.Printf("  %s%s  type=%s\n", safe(k.Fingerprint), primary, safe(k.IdentityType))
	}
	fmt.Println()
	return nil
}

func newIdentitySyncCmd() *cobra.Command {
	var identityFP string

	cmd := &cobra.Command{
		Use:     "sync",
		Aliases: []string{"push"},
		Short:   "Upload public keys (alias: push)",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			dbg("identity.sync", "starting sync, identity_fp=%q", identityFP)
			c, err := newAuthenticatedClient()
			if err != nil {
				return err
			}

			var kp *crypto.KeyPair
			var fp string

			steps := []step{
				{
					label: "Fetching existing remote keys",
					action: func() (string, error) {
						remoteFPs := make(map[string]string)
						remoteKeys, _ := c.ListRemoteKeys()
						dbg("identity.sync", "remote keys found: %d", len(remoteKeys))
						for _, k := range remoteKeys {
							remoteFPs[k.Fingerprint] = k.ID
						}

						// Resolve which local key to sync
						var resolved string
						if identityFP != "" {
							resolved = resolveIdentityName(identityFP)
						} else {
							localKeys, _ := listKeyPairs()
							var unsynced []string
							for _, lk := range localKeys {
								if _, synced := remoteFPs[lk]; !synced {
									unsynced = append(unsynced, lk)
								}
							}
							if len(unsynced) == 1 {
								resolved = unsynced[0]
							} else if len(unsynced) > 1 {
								fmt.Fprintf(os.Stderr, "  Multiple unsynced identities found. Specify one with -i <fingerprint>\n\n")
								for _, u := range unsynced {
									fmt.Fprintf(os.Stderr, "    %s\n", u)
								}
								fmt.Println()
								return "", fmt.Errorf("ambiguous: %d unsynced identities", len(unsynced))
							} else {
								resolved = resolveIdentityName("")
							}
						}

						kp, err = loadKeyPair(resolved)
						if err != nil {
							return "", fmt.Errorf("identity not found. Run: secret identity generate")
						}
						fp, _ = crypto.Fingerprint(kp)

						if _, alreadySynced := remoteFPs[fp]; alreadySynced {
							return "", fmt.Errorf("identity %s is already synced", fp[:16])
						}

						return fmt.Sprintf("remote_keys=%d, local=%s", len(remoteKeys), fp[:16]), nil
					},
				},
				{
					label: "Signing key bundle",
					action: func() (string, error) {
						_, _, err := crypto.SignKeyBundle(kp)
						if err != nil {
							return "", fmt.Errorf("sign key bundle: %w", err)
						}
						return fmt.Sprintf("algo=Ed25519+ML-DSA-65, fingerprint=%s", fp[:16]), nil
					},
				},
				{
					label: "Uploading public keys",
					action: func() (string, error) {
						if err := c.SyncIdentity(kp); err != nil {
							return "", fmt.Errorf("sync failed: %w", err)
						}
						return fmt.Sprintf("fingerprint=%s", fp[:16]), nil
					},
				},
				{
					label: "Setting as primary key",
					action: func() (string, error) {
						keys, err := c.ListRemoteKeys()
						if err != nil {
							return "", fmt.Errorf("fetch keys: %w", err)
						}
						for _, k := range keys {
							if fingerprintMatch(k.Fingerprint, fp) {
								if err := c.SetPrimaryKey(k.ID); err != nil {
									return "", fmt.Errorf("set primary: %w", err)
								}
								return fmt.Sprintf("fingerprint=%s", crypto.ShortFingerprint(fp)), nil
							}
						}
						return fmt.Sprintf("fingerprint=%s", fp[:16]), nil
					},
				},
			}

			if err := runPipeline("Identity Sync", steps, nil); err != nil {
				return err
			}

			printSuccess(fmt.Sprintf("Public keys synced and set as primary. Fingerprint: %s", fp))
			return nil
		},
	}

	cmd.Flags().VarP(&fingerprintFlag{&identityFP}, "identity", "i", "Local identity `fingerprint`, or a prefix of 16+ characters")
	setGroup(cmd.Flags(), groupIdentity, "identity")
	return cmd
}

func newIdentityShowCmd() *cobra.Command {
	var identityFP string

	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show public keys for a local identity",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			resolved := resolveIdentityName(identityFP)
			kp, err := loadKeyPair(resolved)
			if err != nil {
				return fmt.Errorf("identity '%s' not found", identityFP)
			}

			fp, _ := crypto.Fingerprint(kp)

			encrypted := isKeyPairEncrypted(resolved)
			lock := ""
			if encrypted {
				lock = " (encrypted)"
			}

			logInfo("ds.identity_show", fmt.Sprintf("loaded identity fingerprint=%s%s", fp[:16], lock))

			printHeader("Identity: " + fp[:16] + lock)
			fmt.Println()
			printKeyValue("Fingerprint", fp[:16]+" "+fp[16:])
			printKeyValue("Ed25519", safe(kp.ED25519Public))
			printKeyValue("X25519", safe(kp.X25519Public))
			printKeyValue("ML-KEM-768", abbrev(kp.MLKEM768PK, 32, 16))
			printKeyValue("ML-DSA-65", abbrev(kp.MLDSA65PK, 32, 16))
			printKeyValue("Algorithm", "X25519 + ML-KEM-768 + AES-256-GCM + Ed25519 + ML-DSA-65")
			fmt.Println()
			return nil
		},
	}

	cmd.Flags().VarP(&fingerprintFlag{&identityFP}, "identity", "i", "Local identity `fingerprint`, or a prefix of 16+ characters")
	setGroup(cmd.Flags(), groupIdentity, "identity")
	return cmd
}

func newIdentitySetPrimaryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set-primary <fingerprint>",
		Short: "Set a synced identity as primary",
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
			fpPrefix := args[0]

			c, err := newAuthenticatedClient()
			if err != nil {
				return err
			}

			var matchedFP string

			steps := []step{
				{
					label: "Fetching remote identities",
					action: func() (string, error) {
						keys, err := c.ListRemoteKeys()
						if err != nil {
							return "", fmt.Errorf("failed to fetch remote keys: %w", err)
						}

						if len(keys) == 0 {
							return "", fmt.Errorf("no remote identities found. Run: secret identity sync")
						}

						var matches int
						for _, k := range keys {
							if fingerprintMatch(k.Fingerprint, fpPrefix) {
								matchedFP = k.Fingerprint
								matches++
							}
						}
						if matches == 0 {
							return "", fmt.Errorf("no remote identity matching '%s'", fpPrefix)
						}
						if matches > 1 {
							return "", fmt.Errorf("ambiguous prefix '%s': it matches %d keys, be more specific", fpPrefix, matches)
						}

						return fmt.Sprintf("found=%d, match=%s", len(keys), matchedFP[:16]), nil
					},
				},
				{
					label: "Setting primary key",
					action: func() (string, error) {
						keys, err := c.ListRemoteKeys()
						if err != nil {
							return "", fmt.Errorf("fetch keys: %w", err)
						}
						for _, k := range keys {
							if fingerprintMatch(k.Fingerprint, matchedFP) {
								if err := c.SetPrimaryKey(k.ID); err != nil {
									return "", fmt.Errorf("failed to set primary: %w", err)
								}
								return fmt.Sprintf("fingerprint=%s", crypto.ShortFingerprint(matchedFP)), nil
							}
						}
						return "", fmt.Errorf("key not found after re-fetch")
					},
				},
			}

			if err := runPipeline("Identity Set Primary", steps, nil); err != nil {
				return err
			}

			printSuccess(fmt.Sprintf("Primary identity set to: %s", matchedFP))
			return nil
		},
	}

	return cmd
}
