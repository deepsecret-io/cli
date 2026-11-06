// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	deepsecret "github.com/deepsecret-io/deepsecret-go"
)

// textLogger is a logger writing text lines to a buffer at level.
func textLogger(level slog.Level) (*slog.Logger, *bytes.Buffer) {
	var b bytes.Buffer
	return slog.New(&moduleHandler{next: &textHandler{out: &b, level: level}}), &b
}

// A text line is hclog's: time, the level padded to one width, the
// modules joined with a dot, the message, then the fields, quoted where
// they need it and without control characters.
func TestTextLogLine(t *testing.T) {
	log, out := textLogger(deepsecret.LevelTrace)
	upload := Module(Module(log, "upload"), "threads")
	upload.Debug("holding", "threads", 1, "reason", "nothing sent yet", "rate", "575.75KiB/s")
	trace(Module(log, "upload"), "part sent", "part", "1/2", "size", Bytes(8<<20), "elapsed", 29595*time.Millisecond)
	log.Info("started", "name", "evil\033[2J", "empty", "")
	log.Warn("retrying", "error", errors.New("connection reset"))

	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	stamp := `\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}(Z|[+-]\d{4}) `
	for i, want := range []string{
		`\[DEBUG\] upload\.threads: holding: threads=1 reason="nothing sent yet" rate=575\.75KiB/s`,
		`\[TRACE\] upload: part sent: part=1/2 size=8\.00MiB elapsed=29\.595s`,
		`\[INFO\]  started: name=evil\?\[2J empty=""`,
		`\[WARN\]  retrying: error="connection reset"`,
	} {
		if i >= len(lines) || !regexp.MustCompile("^"+stamp+want+"$").MatchString(lines[i]) {
			t.Fatalf("line %d:\n got %q\nwant %s", i, lines, want)
		}
	}
}

// A JSON line has hclog's keys, one @module however deep, and exact
// numbers for sizes.
func TestJSONLogLine(t *testing.T) {
	var b bytes.Buffer
	log := slog.New(&moduleHandler{next: slog.NewJSONHandler(&b, &slog.HandlerOptions{Level: deepsecret.LevelTrace, ReplaceAttr: hclogJSONKeys})})
	trace(Module(Module(log, "upload"), "threads"), "holding", "size", Bytes(8<<20))
	var got map[string]any
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatalf("%v: %s", err, b.String())
	}
	if got["@level"] != "trace" || got["@message"] != "holding" || got["@module"] != "upload.threads" || got["size"] != float64(8<<20) {
		t.Fatalf("%v", got)
	}
	if _, err := time.Parse(hclogTime, got["@timestamp"].(string)); err != nil {
		t.Fatalf("@timestamp %v: %v", got["@timestamp"], err)
	}
	if strings.Count(b.String(), "@module") != 1 {
		t.Fatalf("one @module per line: %s", b.String())
	}
}

// Logs are off unless asked for. --debug and DS_LOG each turn them on,
// and the more detailed level of the two wins. DS_LOG_PATH sends them to a
// file only the user can read.
func TestSetupLogging(t *testing.T) {
	saved := Log
	t.Cleanup(func() { Log = saved })
	enabled := func(l slog.Level) bool { return Log.Enabled(context.Background(), l) }

	for _, c := range []struct {
		env   string
		debug bool
		on    slog.Level // the most detailed level logged
	}{
		{"", false, logsOff},
		{"", true, slog.LevelDebug},
		{"warn", false, slog.LevelWarn},
		{"WARN", true, slog.LevelDebug},
		{"trace", true, deepsecret.LevelTrace},
		{"json", false, deepsecret.LevelTrace},
	} {
		t.Setenv("DS_LOG", c.env)
		err := Setup(c.debug)
		if err != nil {
			t.Fatal(err)
		}
		Close()
		if c.on == logsOff {
			if enabled(slog.LevelError) {
				t.Errorf("DS_LOG=%q debug=%v: logs on", c.env, c.debug)
			}
			continue
		}
		if !enabled(c.on) || enabled(c.on-1) {
			t.Errorf("DS_LOG=%q debug=%v: want %v and above", c.env, c.debug, c.on)
		}
	}

	t.Setenv("DS_LOG", "loud")
	if err := Setup(false); err == nil || !strings.Contains(err.Error(), "trace, debug, info, warn, error or json") {
		t.Fatalf("an unknown DS_LOG: %v", err)
	}

	path := filepath.Join(t.TempDir(), "ds.log")
	t.Setenv("DS_LOG", "json")
	t.Setenv("DS_LOG_PATH", path)
	err := Setup(false)
	if err != nil {
		t.Fatal(err)
	}
	Module(Log, "auth").Debug("key read")
	Close()
	b, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(b), `"@module":"auth"`) {
		t.Fatalf("log file: %q, %v", b, err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("log file mode %v, want 0600", fi.Mode().Perm())
	}
}

// trace logs at the trace level, as the SDK does for each request and part.
func trace(l *slog.Logger, msg string, args ...any) {
	l.Log(context.Background(), deepsecret.LevelTrace, msg, args...)
}
