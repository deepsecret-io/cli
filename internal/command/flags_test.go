// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/deepsecret-io/cli/internal/errs"
	"github.com/deepsecret-io/cli/internal/flags"
)

// runRoot runs the CLI with args and returns its error. Every case that
// uses it fails before any network call.
func runRoot(args ...string) error {
	root := newRootCmd("dev")
	root.SetArgs(args)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	return root.Execute()
}

const testID = "10000000-0000-4000-8000-000000000001"

// fullFP is a well-formed full key fingerprint.
const fullFP = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// Every bad value or combination is refused before anything runs, with an
// error that names what is wrong.
func TestFlagAndArgumentChecks(t *testing.T) {
	dir := t.TempDir()
	// The system's own words for a missing file, which differ on Windows.
	_, statErr := os.Lstat(dir + "/missing")
	missing := "cannot read " + dir + "/missing: " + errs.PathCause(statErr).Error()
	cases := []struct {
		args []string
		want string
	}{
		// encrypt: values
		{[]string{"encrypt", "-d", "K=V", "--threads", "33"}, `"--threads" flag: must be a whole number from 0 to 32`},
		{[]string{"encrypt", "-d", "K=V", "--threads", "-1"}, `"--threads" flag`},
		{[]string{"encrypt", "-d", "K=V", "--threads", "four"}, `"--threads" flag`},
		{[]string{"encrypt", "-d", "K=V", "--presign-expiry", "15"}, "must be whole minutes from 1m to 30m"},
		{[]string{"encrypt", "-d", "K=V", "--presign-expiry", "45m"}, "must be whole minutes from 1m to 30m"},
		{[]string{"encrypt", "-d", "K=V", "--presign-expiry", "90s"}, "must be whole minutes"},
		{[]string{"encrypt", "-d", "K=V", "--ttl", "1.5h"}, `"--ttl" flag: must be a whole number`},
		{[]string{"encrypt", "-d", "K=V", "--ttl", "1m"}, "must be from 2m to 365d"},
		{[]string{"encrypt", "-d", "K=V", "--ttl", "400d"}, "must be from 2m to 365d"},
		{[]string{"encrypt", "-d", "K=V", "--ip", "300.1.1.1"}, "is not an IP address or CIDR"},
		{[]string{"encrypt", "-d", "K=V", "--ip", "10.0.0.0/33"}, "is not an IP address or CIDR"},
		{[]string{"encrypt", "-d", "K=V", "-t", "nobody"}, "invalid recipient email"},
		{[]string{"encrypt", "-d", "K=V", "-t", "a@example.com,A@example.com"}, "listed twice"},
		{[]string{"encrypt", "-d", "K=V", "-t", "a@example.com,"}, "an email is empty"},
		{[]string{"encrypt", "-d", "novalue"}, "must be KEY=VALUE"},
		{[]string{"encrypt", "-d", "=v"}, "must be KEY=VALUE"},
		{[]string{"encrypt", "-d", "K=1", "-d", "K=2"}, `key "K" is given twice`},
		{[]string{"encrypt", "-d", "K=V", "-n", "a<b>"}, `must not contain "<"`},
		{[]string{"encrypt", "-d", "K=V", "-n", "  "}, "not blank"},
		{[]string{"encrypt", "-d", "K=V", "-i", "../../etc/passwd"}, "16 to 64 hex characters"},
		{[]string{"encrypt", "-d", "K=V", "-i", "abcd"}, "16 to 64 hex characters"},
		// encrypt: combinations
		{[]string{"encrypt", "-d", "K=V", "-t", "a@example.com", "-g", "eng"}, "none of the others can be"},
		{[]string{"encrypt", "-f", "x", "-d", "K=V"}, "none of the others can be"},
		{[]string{"encrypt", "x", "-d", "K=V"}, "give files or --data, not both"},
		{[]string{"encrypt", "-f", dir + "/missing"}, missing},
		{[]string{"encrypt", dir, dir + "/missing", "-t", "a@example.com"}, missing},
		{[]string{"encrypt", "-d", "K=V", "--local", "--ttl", "1h"}, "none of the others can be"},
		{[]string{"encrypt", "-d", "K=V", "--local", "--threads", "8"}, "none of the others can be"},
		{[]string{"encrypt", "-d", "K=V", "-o", "x.cbor"}, "--output only applies with --local"},
		{[]string{"encrypt", "-d", "K=V", "--overwrite"}, "--overwrite only applies with --local"},
		{[]string{"encrypt", "-d", "K=V", "--local", "-o", dir}, "is a directory"},
		{[]string{"encrypt", "-d", "K=V", "--local", "-o", dir + "/missing/x.cbor"}, "does not exist"},
		{[]string{"encrypt", "-d", "K=V", "-g", "  "}, "--group needs a group name"},
		// decrypt
		{[]string{"decrypt"}, "accepts 1 arg(s), received 0"},
		{[]string{"decrypt", "not-an-id"}, `invalid secret ID "not-an-id"`},
		{[]string{"decrypt", testID, testID}, "accepts 1 arg(s), received 2"},
		{[]string{"decrypt", testID, "-r", "7"}, `--revision" flag: must be an ID`},
		{[]string{"decrypt", testID, "--threads", "65"}, "must be a whole number from 0 to 64"},
		{[]string{"decrypt", testID, "-o", dir}, "is a directory"},
		{[]string{"decrypt", "--local", "x.cbor", "-r", testID}, "none of the others can be"},
		{[]string{"decrypt", "--local", dir + "/x.cbor"}, "x.cbor"},
		{[]string{"decrypt", "--local", dir}, "is not a file"},
		{[]string{"decrypt", testID, "--force"}, "unknown flag: --force"},
		{[]string{"decrypt", testID, "-t", "4"}, "unknown shorthand flag: 't'"},
		// list and describe
		{[]string{"list", "--limit", "0"}, "must be a whole number from 1 to 1000"},
		{[]string{"list", "--limit", "1001"}, "must be a whole number from 1 to 1000"},
		{[]string{"list", "--page", "0"}, `"--page" flag`},
		{[]string{"list", "--format", "xml"}, "must be one of: table, json, yaml"},
		{[]string{"list", "--vault"}, "unknown flag: --vault"},
		{[]string{"list", "--to", "a@example.com"}, "use --from (not --to)"},
		{[]string{"list", "--sent", "--from", "a@example.com"}, "use --to (not --from)"},
		{[]string{"list", "--no-pagination", "--page", "2"}, "none of the others can be"},
		{[]string{"list", "--from", "nobody"}, "invalid recipient email"},
		{[]string{"list", "extra"}, `unknown command "extra"`},
		{[]string{"describe", "abc"}, `invalid secret ID "abc"`},
		{[]string{"describe", testID, "--all", "-r", testID}, "none of the others can be"},
		{[]string{"describe", testID, "-o", "json"}, "unknown shorthand flag: 'o'"},
		// delete, revoke, policy
		{[]string{"delete"}, "requires at least 1 arg(s)"},
		{[]string{"delete", testID, "nope"}, `invalid secret ID "nope"`},
		{[]string{"revoke", testID}, `required flag(s) "to" not set`},
		{[]string{"revoke", "nope", "-t", "a@example.com"}, `invalid secret ID "nope"`},
		{[]string{"policy", testID}, "at least one of the flags in the group"},
		{[]string{"policy", testID, "--ttl", "1h", "--clear-ttl"}, "none of the others can be"},
		{[]string{"policy", testID, "--ip", "nope"}, "is not an IP address or CIDR"},
		// resume, identity, the rest
		{[]string{"resume", "zz"}, `invalid ID "zz"`},
		{[]string{"resume", "abc"}, `invalid ID "abc"`},
		{[]string{"resume", "3f2a", "--discard", "--threads", "2"}, "none of the others can be"},
		{[]string{"identity", "set-primary", "xyz"}, "16 to 64 hex characters"},
		{[]string{"identity", "show", "-i", "../key"}, "16 to 64 hex characters"},
		{[]string{"identity", "list", "extra"}, `unknown command "extra"`},
		{[]string{"identity", "accept", "bob@example.com"}, "accepts 2 arg(s), received 1"},
		{[]string{"identity", "accept", "nobody", fullFP}, "invalid recipient email"},
		{[]string{"identity", "accept", "bob@example.com", fullFP[:16]}, "give the full 64-character fingerprint"},
		{[]string{"identity", "accept", "bob@example.com", "../" + fullFP}, "give the full 64-character fingerprint"},
		{[]string{"identity", "verify"}, "accepts between 1 and 2 arg(s), received 0"},
		{[]string{"identity", "verify", "bob@example.com", "xyz"}, "give the full 64-character fingerprint"},
		{[]string{"identity", "forget", "bob@example.com", fullFP[:20]}, "give the full 64-character fingerprint"},
		{[]string{"identity", "forget", "a b@example.com"}, "invalid recipient email"},
		{[]string{"identity", "known", "a@example.com", "b@example.com"}, "accepts at most 1 arg(s), received 2"},
		{[]string{"identity", "known", "nobody"}, "invalid recipient email"},
		{[]string{"groups", "describe", " "}, "the group name is blank"},
		{[]string{"whoami", "extra"}, `unknown command "extra"`},
		{[]string{"config", "--api-key", "a", "--api-key-file", "b"}, "none of the others can be"},
		{[]string{"config", "extra"}, `unknown command "extra"`},
	}
	for _, c := range cases {
		err := runRoot(c.args...)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("secret %s: got %v, want an error containing %q", strings.Join(c.args, " "), err, c.want)
		}
	}
}

// Valid values parse as given, including what a naive parser gets wrong:
// a value with commas, an alias, a duration in hours.
func TestFlagValuesThatParse(t *testing.T) {
	cmd := newEncryptCmd()
	err := cmd.ParseFlags([]string{
		"-d", "LIST=a,b,c", "-d", "URL=postgres://u:p@h/db?x=1",
		"-t", "a@example.com,b@example.com", "-t", "c@example.com",
		"--ip", "10.0.0.0/8, 192.168.1.1;2001:db8::/32", "--ip", "10.0.0.0/8",
		"--ttl", "24h", "--presign-expiry", "30m", "--threads", "8",
		"--hide-metadata", "-i", "ABCDEF0123456789", "--snapshot",
	})
	if err != nil {
		t.Fatal(err)
	}
	get := func(name string) string { return cmd.Flags().Lookup(name).Value.String() }
	for name, want := range map[string]string{
		"data":           "LIST=a,b,c,URL=postgres://u:p@h/db?x=1",
		"to":             "a@example.com,b@example.com,c@example.com",
		"ip":             "10.0.0.0/8,192.168.1.1,2001:db8::/32",
		"ttl":            "24h",
		"presign-expiry": "30m",
		"threads":        "8",
		"archive":        "true",
		"identity":       "abcdef0123456789",
		"snapshot":       "true",
	} {
		if got := get(name); got != want {
			t.Errorf("--%s: got %q, want %q", name, got, want)
		}
	}
	if flags.TTLSeconds("7d") != 7*86400 || flags.TTLSeconds("30m") != 1800 {
		t.Error("ttlSeconds")
	}
}

// Help lists every flag under a group, in the fixed order.
func TestEveryFlagHasAHelpGroup(t *testing.T) {
	known := map[string]bool{}
	for _, g := range flags.FlagGroupOrder {
		known[g] = true
	}
	walk(newRootCmd("dev"), func(c *cobra.Command) {
		c.LocalNonPersistentFlags().VisitAll(func(f *pflag.Flag) {
			g := f.Annotations[flags.FlagGroupKey]
			if len(g) != 1 || !known[g[0]] {
				t.Errorf("%s --%s has no help group", c.CommandPath(), f.Name)
			}
		})
	})
	root := newRootCmd("dev")
	root.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		if g := f.Annotations[flags.FlagGroupKey]; len(g) != 1 || g[0] != flags.GroupGlobal {
			t.Errorf("--%s is not in the Global group", f.Name)
		}
	})

	var help bytes.Buffer
	enc, _, err := root.Find([]string{"encrypt"})
	if err != nil {
		t.Fatal(err)
	}
	enc.SetOut(&help)
	if err := enc.Usage(); err != nil {
		t.Fatal(err)
	}
	out := help.String()
	last := -1
	for _, g := range []string{"Recipients:", "Input:", "Policies:", "Local files:", "Identity:", "Performance:", "Global:"} {
		i := strings.Index(out, "\n"+g+"\n")
		if i < 0 || i < last {
			t.Fatalf("encrypt help: %q missing or out of order:\n%s", g, out)
		}
		last = i
	}
	perf := out[strings.Index(out, "\nPerformance:\n"):strings.Index(out, "\nGlobal:\n")]
	if !strings.Contains(perf, "--threads") || !strings.Contains(perf, "--presign-expiry duration") || !strings.Contains(perf, "(default 15m)") {
		t.Errorf("encrypt Performance group:\n%s", perf)
	}
	if strings.Contains(out, "hide-metadata ") || strings.Contains(out, "(default [])") {
		t.Errorf("encrypt help shows an alias as a flag, or an empty list default:\n%s", out)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }

// Usage that cannot be written returns the write error, instead of
// dropping it.
func TestUsageReportsAFailedWrite(t *testing.T) {
	root := newRootCmd("dev")
	root.SetOut(failingWriter{})
	if err := root.Usage(); err == nil {
		t.Fatal("usage into a failing writer returned no error")
	}
}

// A short flag means one thing in every command that has it.
func TestShortFlagsMeanOneThing(t *testing.T) {
	seen := map[string]string{}
	walk(newRootCmd("dev"), func(c *cobra.Command) {
		c.LocalNonPersistentFlags().VisitAll(func(f *pflag.Flag) {
			if f.Shorthand == "" {
				return
			}
			if long, ok := seen[f.Shorthand]; ok && long != f.Name {
				t.Errorf("-%s is --%s in %s but --%s elsewhere", f.Shorthand, f.Name, c.CommandPath(), long)
			}
			seen[f.Shorthand] = f.Name
		})
	})
}

// walk visits every command of the tree but cobra's generated ones.
func walk(c *cobra.Command, fn func(*cobra.Command)) {
	if c.Name() == "completion" || c.Name() == "help" {
		return
	}
	fn(c)
	for _, sub := range c.Commands() {
		walk(sub, fn)
	}
}

// Hostile values are refused at the flag: emails that would change an API
// path or a terminal, keys with control characters, oversized key files.
func TestHostileFlagValues(t *testing.T) {
	big := filepath.Join(t.TempDir(), "big.key")
	if err := os.WriteFile(big, bytes.Repeat([]byte("k"), maxAPIKeyLen+1), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"encrypt", "-d", "K=V", "-t", "../../actors/me@x.io"}, "invalid recipient email"},
		{[]string{"encrypt", "-d", "K=V", "-t", "a\x1b[31m@example.com"}, "invalid recipient email"},
		{[]string{"encrypt", "-d", "K=V", "-t", "alice@example.com\r\nX-Injected: 1"}, "invalid recipient email"},
		{[]string{"list", "--from", "a b@example.com"}, "invalid recipient email"},
		{[]string{"encrypt", "-d", "K\x1b[2J=V"}, "must be KEY=VALUE"},
		{[]string{"encrypt", "-d", "K\u202e=V"}, "must be KEY=VALUE"},
		{[]string{"encrypt", "-d", "K=V", "-n", "name\x1b]0;x\x07"}, "control characters"},
		{[]string{"whoami", "--api-key-file", big}, "over 4096 bytes"},
		{[]string{"encrypt", "-d", "K=V", "--threads", "9999999999999999999999"}, `"--threads" flag`},
		{[]string{"encrypt", "-d", "K=V", "--ttl", "99999999999d"}, `"--ttl" flag`},
		{[]string{"encrypt", "-d", "K=V", "--presign-expiry", "-5m"}, "must be whole minutes"},
		{[]string{"decrypt", "../../../etc/passwd"}, `invalid secret ID`},
		{[]string{"identity", "show", "-i", `..\..\keys`}, "16 to 64 hex characters"},
		{[]string{"identity", "show", "-i", "C:\\Windows\\x"}, "16 to 64 hex characters"},
		{[]string{"resume", "../x"}, "invalid ID"},
	}
	for _, c := range cases {
		err := runRoot(c.args...)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("secret %q: got %v, want an error containing %q", c.args, err, c.want)
		}
	}
}
