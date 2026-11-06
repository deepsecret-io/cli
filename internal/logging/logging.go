// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package logging sets up the CLI's diagnostic log from --debug, DS_LOG and
// DS_LOG_PATH. What a command reports to its user is not a log: see package
// ui.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	deepsecret "github.com/deepsecret-io/deepsecret-go"

	"github.com/deepsecret-io/cli/internal/console"
)

// Logs, as Terraform writes them. They are off unless asked for: --debug
// turns on the debug level, and DS_LOG sets trace, debug, info, warn or
// error, or json for every level as JSON; the more detailed of the two
// wins. They go to stderr, above any live progress, or with DS_LOG_PATH
// are appended to that file. A text line reads
//
//	2026-10-31T02:46:41.120Z [DEBUG] upload.threads: holding: threads=1 reason="nothing sent yet"
//
// and a JSON line carries @timestamp, @level, @module and @message, as
// hclog's do, with the record's fields. The SDK logs through the same
// logger, so its transfer plans and decisions are in the same stream.
//
// Logs are for diagnosis. What a command reports to its user (its steps,
// results, warnings and errors) is its output, printed whatever the log
// level.

// Log is the CLI's logger, set by Setup before a command runs.
// Code logs through a module of it: Module(logger, "encrypt").
var Log = slog.New(slog.DiscardHandler)

// logLevels are the DS_LOG values and the level each turns on.
var logLevels = map[string]slog.Level{
	"trace": deepsecret.LevelTrace,
	"debug": slog.LevelDebug,
	"info":  slog.LevelInfo,
	"warn":  slog.LevelWarn,
	"error": slog.LevelError,
	"json":  deepsecret.LevelTrace,
}

// logsOff is a level above every record's, so nothing is logged.
const logsOff = slog.Level(100)

// Close closes the log file DS_LOG_PATH names, once the command is
// done.
var Close = func() {}

// Setup sets logger from --debug (debugFlag), DS_LOG and
// DS_LOG_PATH. Close closes the log file.
func Setup(debugFlag bool) error {
	level, asJSON := logsOff, false
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("DS_LOG"))); v != "" {
		l, ok := logLevels[v]
		if !ok {
			return fmt.Errorf("DS_LOG=%q is not a log level: use trace, debug, info, warn, error or json", console.Safe(v))
		}
		level, asJSON = l, v == "json"
	}
	if debugFlag {
		level = min(level, slog.LevelDebug)
	}
	if level == logsOff {
		Log = slog.New(slog.DiscardHandler)
		return nil
	}

	var w io.Writer = stderrAboveLive{}
	color := console.Reset != ""
	if path := os.Getenv("DS_LOG_PATH"); path != "" {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600) // #nosec G304 G703 -- the path the user set in DS_LOG_PATH
		if err != nil {
			return fmt.Errorf("could not open the log file DS_LOG_PATH names: %w", err)
		}
		w, Close, color = f, func() { _ = f.Close() }, false
	}
	var h slog.Handler
	if asJSON {
		h = slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level, ReplaceAttr: hclogJSONKeys})
	} else {
		h = &textHandler{out: &lockedWriter{w: w}, level: level, color: color}
	}
	Log = slog.New(&moduleHandler{next: h})
	return nil
}

// stderrAboveLive writes to stderr above the live progress view, so a log
// line never lands inside it.
type stderrAboveLive struct{}

func (stderrAboveLive) Write(p []byte) (int, error) {
	var n int
	var err error
	console.AboveLive(func() { n, err = os.Stderr.Write(p) })
	return n, err
}

// lockedWriter writes one line at a time.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// moduleKey is the field a record's joined module goes in.
const moduleKey = "@module"

// moduleHandler joins the modules a logger was given (logging.Module, nested)
// with a dot into one moduleKey field, as hclog's named loggers do.
type moduleHandler struct {
	next   slog.Handler
	module string
}

func joinModule(a, b string) string {
	if a == "" {
		return b
	}
	return a + "." + b
}

func (h *moduleHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.next.Enabled(ctx, l)
}

func (h *moduleHandler) Handle(ctx context.Context, r slog.Record) error {
	module := h.module
	out := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == deepsecret.LogModuleKey {
			module = joinModule(module, a.Value.String())
		} else {
			out.AddAttrs(a)
		}
		return true
	})
	if module != "" {
		out.AddAttrs(slog.String(moduleKey, module))
	}
	return h.next.Handle(ctx, out)
}

func (h *moduleHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	module := h.module
	var rest []slog.Attr
	for _, a := range attrs {
		if a.Key == deepsecret.LogModuleKey {
			module = joinModule(module, a.Value.String())
		} else {
			rest = append(rest, a)
		}
	}
	next := h.next
	if len(rest) > 0 {
		next = next.WithAttrs(rest)
	}
	return &moduleHandler{next: next, module: module}
}

func (h *moduleHandler) WithGroup(name string) slog.Handler {
	return &moduleHandler{next: h.next.WithGroup(name), module: h.module}
}

// levelName is a level's name: trace below debug, then slog's own.
func levelName(l slog.Level) string {
	if l < slog.LevelDebug {
		return "TRACE"
	}
	return l.String()
}

// hclogJSONKeys gives a JSON record hclog's keys: @timestamp, @level (in
// lower case), @message and @module.
func hclogJSONKeys(groups []string, a slog.Attr) slog.Attr {
	if len(groups) > 0 {
		return a
	}
	switch a.Key {
	case slog.TimeKey:
		return slog.String("@timestamp", a.Value.Time().Format(hclogTime))
	case slog.LevelKey:
		return slog.String("@level", strings.ToLower(levelName(a.Value.Any().(slog.Level))))
	case slog.MessageKey:
		return slog.String("@message", a.Value.String())
	}
	return a
}

// hclogTime is the timestamp layout of hclog's lines.
const hclogTime = "2006-01-02T15:04:05.000Z0700"

// textHandler writes hclog's text lines: time, [LEVEL], module, message
// and the fields as key=value.
type textHandler struct {
	out    io.Writer
	level  slog.Level
	color  bool
	prefix string // the group the fields are in, with a trailing dot
	attrs  []slog.Attr
}

func (h *textHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level }

func (h *textHandler) Handle(_ context.Context, r slog.Record) error {
	var module string
	var fields []string
	add := func(prefix string, a slog.Attr) {
		if a.Key == moduleKey {
			module = a.Value.String()
			return
		}
		if a.Equal(slog.Attr{}) {
			return
		}
		fields = append(fields, prefix+a.Key+"="+logValue(a.Value))
	}
	for _, a := range h.attrs {
		add("", a)
	}
	r.Attrs(func(a slog.Attr) bool {
		add(h.prefix, a)
		return true
	})

	var b strings.Builder
	b.WriteString(r.Time.Format(hclogTime))
	b.WriteByte(' ')
	tag := "[" + levelName(r.Level) + "]"
	if h.color {
		tag = levelColor(r.Level) + tag + console.Reset
	}
	b.WriteString(tag)
	b.WriteString(strings.Repeat(" ", 8-len(levelName(r.Level))-2))
	if module != "" {
		b.WriteString(module)
		b.WriteString(": ")
	}
	b.WriteString(console.Safe(r.Message))
	if len(fields) > 0 {
		b.WriteString(": ")
		b.WriteString(strings.Join(fields, " "))
	}
	b.WriteByte('\n')
	_, err := io.WriteString(h.out, b.String())
	return err
}

func (h *textHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	c := *h
	c.attrs = append(append([]slog.Attr(nil), h.attrs...), prefixed(h.prefix, attrs)...)
	return &c
}

func (h *textHandler) WithGroup(name string) slog.Handler {
	c := *h
	c.prefix = h.prefix + name + "."
	return &c
}

// prefixed returns attrs with prefix put before each key.
func prefixed(prefix string, attrs []slog.Attr) []slog.Attr {
	if prefix == "" {
		return attrs
	}
	out := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		out[i] = slog.Attr{Key: prefix + a.Key, Value: a.Value}
	}
	return out
}

// levelColor is the color of a level's tag on a terminal.
func levelColor(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return console.BoldRed
	case l >= slog.LevelWarn:
		return console.Yellow
	case l >= slog.LevelInfo:
		return console.Cyan
	}
	return console.Dim
}

// logValue is a field's value on a text line, through safe, and quoted
// when it is empty or holds a space, an equals sign or a quote.
func logValue(v slog.Value) string {
	v = v.Resolve()
	var s string
	switch v.Kind() {
	case slog.KindTime:
		s = v.Time().Format(hclogTime)
	case slog.KindDuration:
		s = v.Duration().String()
	case slog.KindAny:
		if err, ok := v.Any().(error); ok {
			s = err.Error()
		} else {
			s = fmt.Sprint(v.Any())
		}
	default:
		s = v.String()
	}
	s = console.Safe(s)
	if s == "" || strings.ContainsAny(s, " =\"") {
		return strconv.Quote(s)
	}
	return s
}

// Module returns l with name added as its module.
func Module(l *slog.Logger, name string) *slog.Logger {
	return l.With(deepsecret.LogModuleKey, name)
}

// Bytes is a byte count. It prints in binary units ("11.01MiB") and encodes in
// JSON as the exact count.
type Bytes int64

func (b Bytes) String() string {
	v := float64(b)
	switch {
	case v >= 1<<30:
		return fmt.Sprintf("%.2fGiB", v/(1<<30))
	case v >= 1<<20:
		return fmt.Sprintf("%.2fMiB", v/(1<<20))
	case v >= 1<<10:
		return fmt.Sprintf("%.2fKiB", v/(1<<10))
	}
	return fmt.Sprintf("%dB", int64(b))
}

// Duration rounds d for a log field: to the millisecond under a
// minute, to the second from there.
func Duration(d time.Duration) time.Duration {
	if d < time.Minute {
		return d.Round(time.Millisecond)
	}
	return d.Round(time.Second)
}
