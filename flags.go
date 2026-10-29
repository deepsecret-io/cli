// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/deepsecret-io/sdk"
)

// ── Flags: help groups, typed values, checks ────────────────────────────────
//
// Every flag belongs to a group, and help lists the groups in one fixed
// order for every command. A short flag means the same thing in every
// command that has it. Values are checked as they are parsed, by typed
// flag values, so a bad value fails before anything runs, with an error
// that names the flag and what it allows.

// flagGroupKey is the pflag annotation that holds a flag's help group.
const flagGroupKey = "deepsecret_group"

// Help groups, in the order help lists them.
const (
	groupRecipients  = "Recipients"
	groupInput       = "Input"
	groupPolicies    = "Policies"
	groupOutput      = "Output"
	groupLocal       = "Local files"
	groupFilters     = "Filters"
	groupPagination  = "Pagination"
	groupIdentity    = "Identity"
	groupOptions     = "Options"
	groupPerformance = "Performance"
	groupGlobal      = "Global"
)

var flagGroupOrder = []string{
	groupRecipients, groupInput, groupPolicies, groupOutput, groupLocal, groupFilters,
	groupPagination, groupIdentity, groupOptions, groupPerformance, groupGlobal,
}

// setGroup puts flags in a help group. It panics on a flag that does not
// exist, so a renamed flag cannot drop out of its group unnoticed.
func setGroup(fs *pflag.FlagSet, group string, names ...string) {
	for _, n := range names {
		if err := fs.SetAnnotation(n, flagGroupKey, []string{group}); err != nil {
			panic(err)
		}
	}
}

// flagGroup is the help group of f. cobra's own help and version flags
// are global; a flag with no group lands in Options.
func flagGroup(f *pflag.Flag) string {
	if g := f.Annotations[flagGroupKey]; len(g) == 1 {
		return g[0]
	}
	if f.Name == "help" || f.Name == "version" {
		return groupGlobal
	}
	return groupOptions
}

// usage prints a command's usage with its flags grouped by responsibility,
// in the layout of cobra's default usage. It writes once, and returns the
// error of that write.
func usage(c *cobra.Command) error {
	var b strings.Builder
	b.WriteString("Usage:\n")
	if c.Runnable() {
		fmt.Fprintf(&b, "  %s\n", c.UseLine())
	}
	if c.HasAvailableSubCommands() {
		fmt.Fprintf(&b, "  %s [command]\n", c.CommandPath())
	}
	if len(c.Aliases) > 0 {
		fmt.Fprintf(&b, "\nAliases:\n  %s\n", c.NameAndAliases())
	}
	if c.HasExample() {
		fmt.Fprintf(&b, "\nExamples:\n%s\n", c.Example)
	}
	if c.HasAvailableSubCommands() {
		b.WriteString("\nAvailable Commands:\n")
		for _, sub := range c.Commands() {
			if sub.IsAvailableCommand() || sub.Name() == "help" {
				fmt.Fprintf(&b, "  %-*s %s\n", c.NamePadding(), sub.Name(), sub.Short)
			}
		}
	}
	writeFlagGroups(&b, c)
	if c.HasAvailableSubCommands() {
		fmt.Fprintf(&b, "\nUse \"%s [command] --help\" for more information about a command.\n", c.CommandPath())
	}
	_, err := io.WriteString(c.OutOrStderr(), b.String())
	return err
}

func writeFlagGroups(b *strings.Builder, c *cobra.Command) {
	// Flags are listed in the order they are declared, which keeps the
	// common ones first.
	c.Flags().SortFlags = false
	sets := map[string]*pflag.FlagSet{}
	add := func(f *pflag.Flag) {
		if f.Hidden {
			return
		}
		g := flagGroup(f)
		if sets[g] == nil {
			sets[g] = pflag.NewFlagSet(g, pflag.ContinueOnError)
			sets[g].SortFlags = false
		}
		if sets[g].Lookup(f.Name) == nil {
			sets[g].AddFlag(f)
		}
	}
	c.LocalFlags().VisitAll(add)
	c.InheritedFlags().VisitAll(add)
	for _, g := range flagGroupOrder {
		if fs := sets[g]; fs != nil && fs.HasAvailableFlags() {
			fmt.Fprintf(b, "\n%s:\n%s", g, fs.FlagUsages())
		}
	}
}

// ── Typed flag values ───────────────────────────────────────────────────────

// intRange is an int flag that refuses values outside [lo, hi]; hint says
// what the values mean.
type intRange struct {
	p      *int
	lo, hi int
	hint   string
}

func newIntRange(p *int, def, lo, hi int, hint string) *intRange {
	*p = def
	return &intRange{p: p, lo: lo, hi: hi, hint: hint}
}

func (v *intRange) String() string { return strconv.Itoa(*v.p) }
func (v *intRange) Type() string   { return "int" }
func (v *intRange) Set(s string) error {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < v.lo || n > v.hi {
		return fmt.Errorf("must be a whole number from %d to %d%s", v.lo, v.hi, v.hint)
	}
	*v.p = n
	return nil
}

// minutesFlag is a duration of whole minutes within [lo, hi] minutes, as
// in 15m. It stores minutes.
type minutesFlag struct {
	p      *int
	lo, hi int
}

func newMinutes(p *int, def, lo, hi int) *minutesFlag {
	*p = def
	return &minutesFlag{p: p, lo: lo, hi: hi}
}

func (v *minutesFlag) String() string { return fmt.Sprintf("%dm", *v.p) }
func (v *minutesFlag) Type() string   { return "duration" }
func (v *minutesFlag) Set(s string) error {
	d, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil || d%time.Minute != 0 || d < time.Duration(v.lo)*time.Minute || d > time.Duration(v.hi)*time.Minute {
		return fmt.Errorf("must be whole minutes from %dm to %dm, like 15m", v.lo, v.hi)
	}
	*v.p = int(d / time.Minute)
	return nil
}

// ttlPattern is a time-to-live: a whole number of minutes, hours or days.
var ttlPattern = regexp.MustCompile(`^([1-9][0-9]{0,8})([mhd])$`)

// The server accepts a time-to-live from 2 minutes to a year.
const (
	minTTLSeconds = 2 * 60
	maxTTLSeconds = 365 * 24 * 60 * 60
)

// ttlFlag is a time-to-live like 30m, 24h or 7d.
type ttlFlag struct{ p *string }

func (v *ttlFlag) String() string { return *v.p }
func (v *ttlFlag) Type() string   { return "ttl" }
func (v *ttlFlag) Set(s string) error {
	s = strings.TrimSpace(s)
	if !ttlPattern.MatchString(s) {
		return errors.New("must be a whole number of minutes (m), hours (h) or days (d), like 30m, 24h or 7d")
	}
	if secs := ttlSeconds(s); secs < minTTLSeconds || secs > maxTTLSeconds {
		return errors.New("must be from 2m to 365d")
	}
	*v.p = s
	return nil
}

// ttlSeconds converts a TTL the ttl flag accepted to seconds.
func ttlSeconds(s string) int64 {
	m := ttlPattern.FindStringSubmatch(s)
	if m == nil {
		return 0
	}
	n, _ := strconv.ParseInt(m[1], 10, 64)
	switch m[2] {
	case "m":
		return n * 60
	case "h":
		return n * 3600
	default:
		return n * 86400
	}
}

// emailList is a repeatable, comma-separated list of recipient emails,
// checked as a whole: plausible addresses, none given twice.
type emailList struct{ p *[]string }

func (v *emailList) String() string { return strings.Join(*v.p, ",") }
func (v *emailList) Type() string   { return "email" }
func (v *emailList) Set(s string) error {
	for _, e := range strings.Split(s, ",") {
		e = strings.TrimSpace(e)
		if e == "" {
			return errors.New("an email is empty")
		}
		*v.p = append(*v.p, e)
	}
	return sdk.ValidateRecipients(*v.p)
}

// emailFlag is one email address.
type emailFlag struct{ p *string }

func (v *emailFlag) String() string { return *v.p }
func (v *emailFlag) Type() string   { return "email" }
func (v *emailFlag) Set(s string) error {
	s = strings.TrimSpace(s)
	if err := sdk.ValidateRecipients([]string{s}); err != nil {
		return err
	}
	*v.p = s
	return nil
}

// maxIPEntries is how many IP-lock entries the server accepts.
const maxIPEntries = 50

// ipList is a repeatable list of IP addresses and CIDR ranges, separated
// by commas, semicolons or spaces. Duplicates are dropped.
type ipList struct{ p *[]string }

func (v *ipList) String() string { return strings.Join(*v.p, ",") }
func (v *ipList) Type() string   { return "ip" }
func (v *ipList) Set(s string) error {
	for _, e := range splitListFlag([]string{s}) {
		if net.ParseIP(e) == nil {
			if _, _, err := net.ParseCIDR(e); err != nil {
				return fmt.Errorf("%q is not an IP address or CIDR range like 10.0.0.0/8", e)
			}
		}
		*v.p = splitListFlag(append(*v.p, e))
	}
	if len(*v.p) > maxIPEntries {
		return fmt.Errorf("at most %d entries", maxIPEntries)
	}
	return nil
}

// fingerprintPattern is a key fingerprint or a prefix of one: hex, at
// least 16 characters so a prefix cannot match the wrong key.
var fingerprintPattern = regexp.MustCompile(`^[0-9a-f]{16,64}$`)

// checkFingerprint checks a fingerprint or prefix and returns it in lower
// case. It is also a file name in the keystore, so nothing else passes.
func checkFingerprint(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if !fingerprintPattern.MatchString(s) {
		return "", errors.New("must be a key fingerprint or a prefix of one: 16 to 64 hex characters")
	}
	return s, nil
}

// fingerprintFlag is a key fingerprint or prefix.
type fingerprintFlag struct{ p *string }

func (v *fingerprintFlag) String() string { return *v.p }
func (v *fingerprintFlag) Type() string   { return "fingerprint" }
func (v *fingerprintFlag) Set(s string) (err error) {
	*v.p, err = checkFingerprint(s)
	return err
}

// uuidFlag is an ID in UUID form, stored in canonical lower case.
type uuidFlag struct{ p *string }

func (v *uuidFlag) String() string { return *v.p }
func (v *uuidFlag) Type() string   { return "id" }
func (v *uuidFlag) Set(s string) error {
	id, err := uuid.Parse(strings.TrimSpace(s))
	if err != nil {
		return errors.New("must be an ID like 3f2a9c1e-6b4d-4e8a-9c2f-1a2b3c4d5e6f")
	}
	*v.p = id.String()
	return nil
}

// enumFlag is one of a fixed set of values.
type enumFlag struct {
	p       *string
	allowed []string
}

func (v *enumFlag) String() string { return *v.p }
func (v *enumFlag) Type() string   { return strings.Join(v.allowed, "|") }
func (v *enumFlag) Set(s string) error {
	s = strings.ToLower(strings.TrimSpace(s))
	for _, a := range v.allowed {
		if s == a {
			*v.p = s
			return nil
		}
	}
	return fmt.Errorf("must be one of: %s", strings.Join(v.allowed, ", "))
}

// nameFlag is a secret's name, as the server accepts it: 1 to 255
// characters, not blank, without "<" or ">" or control characters.
type nameFlag struct{ p *string }

func (v *nameFlag) String() string { return *v.p }
func (v *nameFlag) Type() string   { return "name" }
func (v *nameFlag) Set(s string) error {
	if err := checkName(s); err != nil {
		return err
	}
	*v.p = s
	return nil
}

func checkName(s string) error {
	if strings.TrimSpace(s) == "" || len([]rune(s)) > 255 {
		return errors.New("must be 1 to 255 characters and not blank")
	}
	for _, r := range s {
		if r == '<' || r == '>' || r < ' ' || r == 0x7f {
			return errors.New(`must not contain "<", ">" or control characters`)
		}
	}
	return nil
}

// dataKeyPattern is a key of a KEY=VALUE pair: printable, without spaces
// or "=".
var dataKeyPattern = regexp.MustCompile(`^[^\s=\p{Cc}\p{Cf}]{1,256}$`)

// kvPairs is a repeatable KEY=VALUE pair. Values are taken whole, commas
// included, and a key may not be given twice.
type kvPairs struct{ p *[]string }

func (v *kvPairs) String() string { return strings.Join(*v.p, ",") }
func (v *kvPairs) Type() string   { return "key=value" }
func (v *kvPairs) Set(s string) error {
	k, _, ok := strings.Cut(s, "=")
	if !ok || !dataKeyPattern.MatchString(k) {
		return errors.New("must be KEY=VALUE, with a key of 1 to 256 characters and no spaces")
	}
	for _, kv := range *v.p {
		if old, _, _ := strings.Cut(kv, "="); old == k {
			return fmt.Errorf("key %q is given twice", k)
		}
	}
	*v.p = append(*v.p, s)
	return nil
}

// ── Argument checks ─────────────────────────────────────────────────────────

// idArgs accepts exactly n arguments, each an ID in UUID form (what names
// it, for the error), and rewrites them in canonical lower case.
func idArgs(n int, what string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if err := cobra.ExactArgs(n)(cmd, args); err != nil {
			return err
		}
		return checkIDs(args, what)
	}
}

// minIDArgs accepts at least n arguments, each an ID in UUID form.
func minIDArgs(n int, what string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if err := cobra.MinimumNArgs(n)(cmd, args); err != nil {
			return err
		}
		return checkIDs(args, what)
	}
}

func checkIDs(args []string, what string) error {
	for i, a := range args {
		id, err := uuid.Parse(strings.TrimSpace(a))
		if err != nil {
			return fmt.Errorf("invalid %s %q: expected an ID like 3f2a9c1e-6b4d-4e8a-9c2f-1a2b3c4d5e6f", what, a)
		}
		args[i] = id.String()
	}
	return nil
}

// requireFlag refuses dependents set without flag: they only apply with it.
func requireFlag(cmd *cobra.Command, flag string, dependents ...string) error {
	if cmd.Flags().Changed(flag) {
		return nil
	}
	for _, d := range dependents {
		if cmd.Flags().Changed(d) {
			return fmt.Errorf("--%s only applies with --%s", d, flag)
		}
	}
	return nil
}

// checkOutputFile refuses an output file path that is a directory or whose
// directory does not exist. flag names it for the error.
func checkOutputFile(flag, path string) error {
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return fmt.Errorf("--%s %s is a directory; give a file path", flag, path)
	}
	dir := filepath.Dir(path)
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("--%s: directory %s does not exist", flag, dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("--%s: %s is not a directory", flag, dir)
	}
	return nil
}
