// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package flags holds the CLI's validated flag types, argument checks and
// grouped help. A flag's value is checked when it is parsed, before a command
// runs.
package flags

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

	"github.com/deepsecret-io/sdk"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/deepsecret-io/cli/internal/fingerprint"
)

// SplitList splits each entry on commas, semicolons, and whitespace,
// trims, and de-duplicates while preserving order. Lets list flags accept
// any of: --ip a --ip b   |   --ip a,b,c   |   --ip "a, b ; c"
func SplitList(values []string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(values))
	for _, v := range values {
		for _, p := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\t' }) {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out
}

// ── Flags: help groups, typed values, checks ────────────────────────────────
//
// Every flag belongs to a group, and help lists the groups in one fixed
// order for every command. A short flag means the same thing in every
// command that has it. Values are checked as they are parsed, by typed
// flag values, so a bad value fails before anything runs, with an error
// that names the flag and what it allows.

// FlagGroupKey is the pflag annotation that holds a flag's help group.
const FlagGroupKey = "deepsecret_group"

// Help groups, in the order help lists them.
const (
	GroupRecipients  = "Recipients"
	GroupInput       = "Input"
	GroupPolicies    = "Policies"
	GroupOutput      = "Output"
	GroupLocal       = "Local files"
	GroupFilters     = "Filters"
	GroupPagination  = "Pagination"
	GroupIdentity    = "Identity"
	GroupOptions     = "Options"
	GroupPerformance = "Performance"
	GroupGlobal      = "Global"
)

// FlagGroupOrder is the order help lists the flag groups in.
var FlagGroupOrder = []string{
	GroupRecipients, GroupInput, GroupPolicies, GroupOutput, GroupLocal, GroupFilters,
	GroupPagination, GroupIdentity, GroupOptions, GroupPerformance, GroupGlobal,
}

// SetGroup puts flags in a help group. It panics on a flag that does not
// exist, so a renamed flag cannot drop out of its group unnoticed.
func SetGroup(fs *pflag.FlagSet, group string, names ...string) {
	for _, n := range names {
		if err := fs.SetAnnotation(n, FlagGroupKey, []string{group}); err != nil {
			panic(err)
		}
	}
}

// flagGroup is the help group of f. cobra's own help and version flags
// are global; a flag with no group lands in Options.
func flagGroup(f *pflag.Flag) string {
	if g := f.Annotations[FlagGroupKey]; len(g) == 1 {
		return g[0]
	}
	if f.Name == "help" || f.Name == "version" {
		return GroupGlobal
	}
	return GroupOptions
}

// Usage prints a command's usage with its flags grouped by responsibility,
// in the layout of cobra's default usage. It writes once, and returns the
// error of that write.
func Usage(c *cobra.Command) error {
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
	for _, g := range FlagGroupOrder {
		if fs := sets[g]; fs != nil && fs.HasAvailableFlags() {
			fmt.Fprintf(b, "\n%s:\n%s", g, fs.FlagUsages())
		}
	}
}

// ── Typed flag values ───────────────────────────────────────────────────────

// IntRange is an int flag that refuses values outside [lo, hi]; hint says
// what the values mean.
type IntRange struct {
	p      *int
	lo, hi int
	hint   string
}

// NewIntRange binds an IntRange flag to p, with the default def.
func NewIntRange(p *int, def, lo, hi int, hint string) *IntRange {
	*p = def
	return &IntRange{p: p, lo: lo, hi: hi, hint: hint}
}

func (v *IntRange) String() string { return strconv.Itoa(*v.p) }

// Type names the value in help, as pflag.Value asks.
func (v *IntRange) Type() string { return "int" }

// Set checks and stores a value given on the command line.
func (v *IntRange) Set(s string) error {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < v.lo || n > v.hi {
		return fmt.Errorf("must be a whole number from %d to %d%s", v.lo, v.hi, v.hint)
	}
	*v.p = n
	return nil
}

// Minutes is a duration of whole minutes within [lo, hi] minutes, as
// in 15m. It stores minutes.
type Minutes struct {
	p      *int
	lo, hi int
}

// NewMinutes binds a Minutes flag to p, with the default def.
func NewMinutes(p *int, def, lo, hi int) *Minutes {
	*p = def
	return &Minutes{p: p, lo: lo, hi: hi}
}

func (v *Minutes) String() string { return fmt.Sprintf("%dm", *v.p) }

// Type names the value in help, as pflag.Value asks.
func (v *Minutes) Type() string { return "duration" }

// Set checks and stores a value given on the command line.
func (v *Minutes) Set(s string) error {
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

// TTL is a time-to-live like 30m, 24h or 7d.
type TTL struct{ p *string }

// NewTTL binds a TTL flag to p.
func NewTTL(p *string) *TTL { return &TTL{p} }

func (v *TTL) String() string { return *v.p }

// Type names the value in help, as pflag.Value asks.
func (v *TTL) Type() string { return "ttl" }

// Set checks and stores a value given on the command line.
func (v *TTL) Set(s string) error {
	s = strings.TrimSpace(s)
	if !ttlPattern.MatchString(s) {
		return errors.New("must be a whole number of minutes (m), hours (h) or days (d), like 30m, 24h or 7d")
	}
	if secs := TTLSeconds(s); secs < minTTLSeconds || secs > maxTTLSeconds {
		return errors.New("must be from 2m to 365d")
	}
	*v.p = s
	return nil
}

// TTLSeconds converts a TTL the ttl flag accepted to seconds.
func TTLSeconds(s string) int64 {
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

// EmailList is a repeatable, comma-separated list of recipient emails,
// checked as a whole: plausible addresses, none given twice.
type EmailList struct{ p *[]string }

// NewEmailList binds a EmailList flag to p.
func NewEmailList(p *[]string) *EmailList { return &EmailList{p} }

func (v *EmailList) String() string { return strings.Join(*v.p, ",") }

// Type names the value in help, as pflag.Value asks.
func (v *EmailList) Type() string { return "email" }

// Set checks and stores a value given on the command line.
func (v *EmailList) Set(s string) error {
	for _, e := range strings.Split(s, ",") {
		e = strings.TrimSpace(e)
		if e == "" {
			return errors.New("an email is empty")
		}
		*v.p = append(*v.p, e)
	}
	return sdk.ValidateRecipients(*v.p)
}

// Email is one email address.
type Email struct{ p *string }

// NewEmail binds a Email flag to p.
func NewEmail(p *string) *Email { return &Email{p} }

func (v *Email) String() string { return *v.p }

// Type names the value in help, as pflag.Value asks.
func (v *Email) Type() string { return "email" }

// Set checks and stores a value given on the command line.
func (v *Email) Set(s string) error {
	s = strings.TrimSpace(s)
	if err := sdk.ValidateRecipients([]string{s}); err != nil {
		return err
	}
	*v.p = s
	return nil
}

// maxIPEntries is how many IP-lock entries the server accepts.
const maxIPEntries = 50

// IPList is a repeatable list of IP addresses and CIDR ranges, separated
// by commas, semicolons or spaces. Duplicates are dropped.
type IPList struct{ p *[]string }

// NewIPList binds a IPList flag to p.
func NewIPList(p *[]string) *IPList { return &IPList{p} }

func (v *IPList) String() string { return strings.Join(*v.p, ",") }

// Type names the value in help, as pflag.Value asks.
func (v *IPList) Type() string { return "ip" }

// Set checks and stores a value given on the command line.
func (v *IPList) Set(s string) error {
	for _, e := range SplitList([]string{s}) {
		if net.ParseIP(e) == nil {
			if _, _, err := net.ParseCIDR(e); err != nil {
				return fmt.Errorf("%q is not an IP address or CIDR range like 10.0.0.0/8", e)
			}
		}
		*v.p = SplitList(append(*v.p, e))
	}
	if len(*v.p) > maxIPEntries {
		return fmt.Errorf("at most %d entries", maxIPEntries)
	}
	return nil
}

// Fingerprint is a key fingerprint or prefix.
type Fingerprint struct{ p *string }

// NewFingerprint binds a Fingerprint flag to p.
func NewFingerprint(p *string) *Fingerprint { return &Fingerprint{p} }

func (v *Fingerprint) String() string { return *v.p }

// Type names the value in help, as pflag.Value asks.
func (v *Fingerprint) Type() string { return "fingerprint" }

// Set checks and stores a value given on the command line.
func (v *Fingerprint) Set(s string) (err error) {
	*v.p, err = fingerprint.Check(s)
	return err
}

// UUID is an ID in UUID form, stored in canonical lower case.
type UUID struct{ p *string }

// NewUUID binds a UUID flag to p.
func NewUUID(p *string) *UUID { return &UUID{p} }

func (v *UUID) String() string { return *v.p }

// Type names the value in help, as pflag.Value asks.
func (v *UUID) Type() string { return "id" }

// Set checks and stores a value given on the command line.
func (v *UUID) Set(s string) error {
	id, err := uuid.Parse(strings.TrimSpace(s))
	if err != nil {
		return errors.New("must be an ID like 3f2a9c1e-6b4d-4e8a-9c2f-1a2b3c4d5e6f")
	}
	*v.p = id.String()
	return nil
}

// Enum is one of a fixed set of values.
type Enum struct {
	p       *string
	allowed []string
}

// NewEnum binds an Enum flag to p; its value must be one of allowed.
func NewEnum(p *string, allowed ...string) *Enum { return &Enum{p, allowed} }

func (v *Enum) String() string { return *v.p }

// Type names the value in help, as pflag.Value asks.
func (v *Enum) Type() string { return strings.Join(v.allowed, "|") }

// Set checks and stores a value given on the command line.
func (v *Enum) Set(s string) error {
	s = strings.ToLower(strings.TrimSpace(s))
	for _, a := range v.allowed {
		if s == a {
			*v.p = s
			return nil
		}
	}
	return fmt.Errorf("must be one of: %s", strings.Join(v.allowed, ", "))
}

// Name is a secret's name, as the server accepts it: 1 to 255
// characters, not blank, without "<" or ">" or control characters.
type Name struct{ p *string }

// NewName binds a Name flag to p.
func NewName(p *string) *Name { return &Name{p} }

func (v *Name) String() string { return *v.p }

// Type names the value in help, as pflag.Value asks.
func (v *Name) Type() string { return "name" }

// Set checks and stores a value given on the command line.
func (v *Name) Set(s string) error {
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

// KVPairs is a repeatable KEY=VALUE pair. Values are taken whole, commas
// included, and a key may not be given twice.
type KVPairs struct{ p *[]string }

// NewKVPairs binds a KVPairs flag to p.
func NewKVPairs(p *[]string) *KVPairs { return &KVPairs{p} }

func (v *KVPairs) String() string { return strings.Join(*v.p, ",") }

// Type names the value in help, as pflag.Value asks.
func (v *KVPairs) Type() string { return "key=value" }

// Set checks and stores a value given on the command line.
func (v *KVPairs) Set(s string) error {
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

// IDArgs accepts exactly n arguments, each an ID in UUID form (what names
// it, for the error), and rewrites them in canonical lower case.
func IDArgs(n int, what string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if err := cobra.ExactArgs(n)(cmd, args); err != nil {
			return err
		}
		return CheckIDs(args, what)
	}
}

// MinIDArgs accepts at least n arguments, each an ID in UUID form.
func MinIDArgs(n int, what string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if err := cobra.MinimumNArgs(n)(cmd, args); err != nil {
			return err
		}
		return CheckIDs(args, what)
	}
}

// CheckIDs refuses an argument that is not an ID; what names it in the error.
func CheckIDs(args []string, what string) error {
	for i, a := range args {
		id, err := uuid.Parse(strings.TrimSpace(a))
		if err != nil {
			return fmt.Errorf("invalid %s %q: expected an ID like 3f2a9c1e-6b4d-4e8a-9c2f-1a2b3c4d5e6f", what, a)
		}
		args[i] = id.String()
	}
	return nil
}

// Require refuses dependents set without flag: they only apply with it.
func Require(cmd *cobra.Command, flag string, dependents ...string) error {
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

// CheckOutputFile refuses an output file path that is a directory or whose
// directory does not exist. flag names it for the error.
func CheckOutputFile(flag, path string) error {
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
