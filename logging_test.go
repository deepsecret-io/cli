// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/deepsecret-io/sdk/api"
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
	log, out := textLogger(api.LevelTrace)
	upload := api.Module(api.Module(log, "upload"), "threads")
	upload.Debug("holding", "threads", 1, "reason", "nothing sent yet", "rate", api.Rate(589567))
	api.Trace(api.Module(log, "upload"), "part sent", "part", "1/2", "size", api.Bytes(8<<20), "elapsed", 29595*time.Millisecond)
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
	log := slog.New(&moduleHandler{next: slog.NewJSONHandler(&b, &slog.HandlerOptions{Level: api.LevelTrace, ReplaceAttr: hclogJSONKeys})})
	api.Trace(api.Module(api.Module(log, "upload"), "threads"), "holding", "size", api.Bytes(8<<20))
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
	saved := logger
	t.Cleanup(func() { logger = saved })
	enabled := func(l slog.Level) bool { return logger.Enabled(context.Background(), l) }

	for _, c := range []struct {
		env   string
		debug bool
		on    slog.Level // the most detailed level logged
	}{
		{"", false, logsOff},
		{"", true, slog.LevelDebug},
		{"warn", false, slog.LevelWarn},
		{"WARN", true, slog.LevelDebug},
		{"trace", true, api.LevelTrace},
		{"json", false, api.LevelTrace},
	} {
		t.Setenv("DS_LOG", c.env)
		closeLog, err := setupLogging(c.debug)
		if err != nil {
			t.Fatal(err)
		}
		closeLog()
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
	if _, err := setupLogging(false); err == nil || !strings.Contains(err.Error(), "trace, debug, info, warn, error or json") {
		t.Fatalf("an unknown DS_LOG: %v", err)
	}

	path := filepath.Join(t.TempDir(), "ds.log")
	t.Setenv("DS_LOG", "json")
	t.Setenv("DS_LOG_PATH", path)
	closeLog, err := setupLogging(false)
	if err != nil {
		t.Fatal(err)
	}
	api.Module(logger, "auth").Debug("key read")
	closeLog()
	b, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(b), `"@module":"auth"`) {
		t.Fatalf("log file: %q, %v", b, err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("log file mode %v, want 0600", fi.Mode().Perm())
	}
}

// A step that runs long without live progress says it is still running.
func TestStepSaysItIsStillRunning(t *testing.T) {
	savedCtx, savedEvery, savedProgress := rootCtx, stillEvery, showProgress
	t.Cleanup(func() { rootCtx, stillEvery, showProgress = savedCtx, savedEvery, savedProgress })
	rootCtx, stillEvery, showProgress = context.Background(), 300*time.Millisecond, false
	out := stderrOf(t, func() {
		_ = runPipeline("secret", []step{{label: "Downloading", done: "Download complete", action: func() (string, error) {
			time.Sleep(750 * time.Millisecond)
			return "", nil
		}}})
	})
	if !strings.Contains(out, "secret: Downloading...\nsecret: Still downloading... [") || !strings.Contains(out, "secret: Download complete after ") {
		t.Fatalf("%q", out)
	}
}

// An Error block is the summary on one line, then the detail indented.
func TestPrintDiagnostic(t *testing.T) {
	out := stderrOf(t, func() {
		printDiagnostic(sevError, "Secret not found", "No secret 0724ba1f is shared with you.\n\nCheck the ID with 'secret list'.")
		printWarning("Key changed", "")
	})
	want := "\nError: Secret not found\n\n  No secret 0724ba1f is shared with you.\n\n  Check the ID with 'secret list'.\n" +
		"\nWarning: Key changed\n"
	if out != want {
		t.Fatalf("got  %q\nwant %q", out, want)
	}
}

// An error's first line, with a capital, is the summary; the rest of its
// message and the detail it carries are the detail.
func TestDescribeError(t *testing.T) {
	err := withDetail(fmt.Errorf("upload interrupted: %w", errors.New("connection reset\n  after 3 attempts")), "The upload can resume:\n  secret resume 7da383f1")
	summary, detail := describeError(err)
	if summary != "Upload interrupted: connection reset" {
		t.Errorf("summary %q", summary)
	}
	if detail != "after 3 attempts\n\nThe upload can resume:\n  secret resume 7da383f1" {
		t.Errorf("detail %q", detail)
	}
}
