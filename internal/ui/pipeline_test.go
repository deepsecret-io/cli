// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package ui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/deepsecret-io/cli/internal/testutil"
)

// A step that runs long without live progress says it is still running.
func TestStepSaysItIsStillRunning(t *testing.T) {
	savedEvery, savedProgress := stillEvery, ShowProgress
	t.Cleanup(func() { stillEvery, ShowProgress = savedEvery, savedProgress })
	stillEvery, ShowProgress = 300*time.Millisecond, false
	out := testutil.StderrOf(t, func() {
		_ = RunPipeline(context.Background(), "secret", []Step{{Label: "Downloading", Done: "Download complete", Action: func() (string, error) {
			time.Sleep(750 * time.Millisecond)
			return "", nil
		}}})
	})
	if !strings.Contains(out, "secret: Downloading...\nsecret: Still downloading... [") || !strings.Contains(out, "secret: Download complete after ") {
		t.Fatalf("%q", out)
	}
}

// A step whose work begins inside its action shows nothing until it
// begins, however long that takes, so a prompt for a PIN stands alone; its
// time counts from then.
func TestStepWaitsForItsPhase(t *testing.T) {
	savedEvery, savedProgress := stillEvery, ShowProgress
	t.Cleanup(func() { stillEvery, ShowProgress = savedEvery, savedProgress })
	stillEvery, ShowProgress = 100*time.Millisecond, false
	begins := NewPhaseStart()
	out := testutil.StderrOf(t, func() {
		err := RunPipeline(context.Background(), "secret", []Step{{Label: "Uploading", Done: "Upload complete", Begins: begins, Action: func() (string, error) {
			fmt.Fprint(os.Stderr, "PIN: ")
			time.Sleep(450 * time.Millisecond) // the PIN is typed
			fmt.Fprintln(os.Stderr)
			begins.Mark()
			time.Sleep(250 * time.Millisecond)
			return "id=1", nil
		}}})
		if err != nil {
			t.Error(err)
		}
	})
	if !strings.HasPrefix(out, "PIN: \nsecret: Uploading...\nsecret: Still uploading... [") {
		t.Fatalf("the step showed before it began: %q", out)
	}
	m := regexp.MustCompile(`Upload complete after (\d+)ms \[id=1\]`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no done line: %q", out)
	}
	if ms, _ := strconv.Atoi(m[1]); ms < 200 || ms >= 450 {
		t.Fatalf("the step took %sms, want its time from when it began", m[1])
	}
}

// A send is one call shown as two steps. A failure while encrypting stops
// the first; a failure while uploading is the second's; a call that never
// says its phases still shows both steps.
func TestCallAcrossSteps(t *testing.T) {
	savedEvery, savedProgress := stillEvery, ShowProgress
	t.Cleanup(func() { stillEvery, ShowProgress = savedEvery, savedProgress })
	stillEvery, ShowProgress = time.Hour, false
	boom := errors.New("boom")
	run := func(fail string, signals bool) (string, error) {
		encrypting, uploading := NewPhaseStart(), NewPhaseStart()
		call := StartCall(func() (string, error) {
			if signals {
				encrypting.Mark()
			}
			if fail == "encrypting" {
				return "", boom
			}
			if signals {
				uploading.Mark()
				fmt.Fprintln(os.Stderr, "creating revision") // an SDK log of the upload
			}
			if fail == "uploading" {
				return "", boom
			}
			return "id=1", nil
		})
		var err error
		out := testutil.StderrOf(t, func() {
			err = RunPipeline(context.Background(), "secret", []Step{
				{Label: "Encrypting", Done: "Encryption complete", Begins: encrypting, Action: func() (string, error) { return call.Until(uploading) }},
				{Label: "Uploading", Done: "Upload complete", Begins: uploading, Action: call.Wait},
			})
		})
		return out, err
	}
	// The upload's logs come after its line, never above it.
	said := regexp.MustCompile(`^secret: Encrypting\.\.\.\nsecret: Encryption complete after \d+ms\nsecret: Uploading\.\.\.\ncreating revision\nsecret: Upload complete after \d+ms \[id=1\]\n$`)
	unsaid := regexp.MustCompile(`^secret: Encrypting\.\.\.\nsecret: Encryption complete after \d+ms\nsecret: Uploading\.\.\.\nsecret: Upload complete after \d+ms \[id=1\]\n$`)
	for i := 0; i < 20; i++ {
		if out, err := run("", true); err != nil || !said.MatchString(out) {
			t.Fatalf("a send: %q, %v", out, err)
		}
	}
	if out, err := run("", false); err != nil || !unsaid.MatchString(out) {
		t.Fatalf("a send that never says its phases: %q, %v", out, err)
	}
	if out, err := run("encrypting", true); !errors.Is(err, boom) || strings.Contains(out, "complete") || strings.Contains(out, "Uploading") {
		t.Fatalf("a failure while encrypting: %q, %v", out, err)
	}
	if out, err := run("uploading", true); !errors.Is(err, boom) || !strings.Contains(out, "secret: Encryption complete after ") || strings.Contains(out, "Upload complete") {
		t.Fatalf("a failure while uploading: %q, %v", out, err)
	}
}

// A step that fails before it begins shows no line of its own, and an
// interrupt while it waits is said once.
func TestStepThatNeverBegins(t *testing.T) {
	savedEvery, savedProgress := stillEvery, ShowProgress
	t.Cleanup(func() { stillEvery, ShowProgress = savedEvery, savedProgress })
	ctx, cancel := context.WithCancel(context.Background())
	stillEvery, ShowProgress = 50*time.Millisecond, false
	wrongPIN := errors.New("wrong PIN")
	var err error
	out := testutil.StderrOf(t, func() {
		err = RunPipeline(ctx, "secret", []Step{{Label: "Encrypting", Done: "Encryption complete", Begins: NewPhaseStart(), Action: func() (string, error) {
			cancel()
			time.Sleep(300 * time.Millisecond)
			return "", wrongPIN
		}}})
	})
	if !errors.Is(err, wrongPIN) {
		t.Fatalf("error %v", err)
	}
	if strings.Contains(out, "Encrypting") || strings.Count(out, "Interrupt received") != 1 {
		t.Fatalf("%q", out)
	}
}

// An Error block is the summary on one line, then the detail indented.
func TestPrintDiagnostic(t *testing.T) {
	out := testutil.StderrOf(t, func() {
		Diagnostic(SevError, "Secret not found", "No secret 0724ba1f is shared with you.\n\nCheck the ID with 'secret list'.")
		Warning("Key changed", "")
	})
	want := "\nError: Secret not found\n\n  No secret 0724ba1f is shared with you.\n\n  Check the ID with 'secret list'.\n" +
		"\nWarning: Key changed\n"
	if out != want {
		t.Fatalf("got  %q\nwant %q", out, want)
	}
}
