// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package ui is what a command shows its user: its steps as they run,
// transfer progress, results, warnings and errors, and the formatting of the
// values in them.
package ui

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/deepsecret-io/cli/internal/console"
	"github.com/deepsecret-io/cli/internal/prompt"
)

// ShowProgress draws a transfer's progress (--progress). Without it the
// output stays plain for pipes, scripts and logs.
var ShowProgress bool

// Step is one unit of a command's work. label says what it does while it
// runs ("Uploading") and done what it did once it finished ("Upload
// complete"). Its action returns a detail for the done line, such as
// "id=0724ba1f", or "".
type Step struct {
	Label          string
	Done           string
	Action         func() (string, error)                        // simple step
	progressAction func(progress chan<- float64) (string, error) // progress-tracked step
	Live           *LiveProgress                                 // live progress (encrypt, upload, download)
	// begins, when set, marks the moment the step's work begins inside its
	// action, as the SDK reports it with OnPhase. Until then the step shows
	// nothing, so a security key's prompt for a PIN or a touch stands
	// alone, and the wait for it is not counted in the step's time.
	Begins *PhaseStart
}

// PhaseStart is the moment an SDK phase began.
type PhaseStart struct {
	once      sync.Once
	ch        chan struct{} // closed when it began
	at        time.Time
	shownOnce sync.Once
	shown     chan struct{} // closed once the step's line is out
}

// NewPhaseStart makes a PhaseStart that has not begun.
func NewPhaseStart() *PhaseStart {
	return &PhaseStart{ch: make(chan struct{}), shown: make(chan struct{})}
}

// phaseShowWait bounds how long mark waits for the step's line.
var phaseShowWait = time.Second

// Mark records that the phase began now, then waits until RunPipeline has
// shown the step's line, so the SDK's logs for the phase come after it;
// later calls do nothing.
func (p *PhaseStart) Mark() {
	first := false
	p.once.Do(func() {
		p.at = time.Now()
		close(p.ch)
		first = true
	})
	if first {
		select {
		case <-p.shown:
		case <-time.After(phaseShowWait):
		}
	}
}

// show says the step's line is out, or will not be: mark need not wait.
func (p *PhaseStart) show() { p.shownOnce.Do(func() { close(p.shown) }) }

// began reports whether the phase began.
func (p *PhaseStart) began() bool {
	select {
	case <-p.ch:
		return true
	default:
		return false
	}
}

// SDKCall is one SDK call that runs across steps, such as a send that
// encrypts in one step and uploads in the next: each step's action waits
// for its part of the call.
type SDKCall struct {
	done   chan struct{}
	detail string
	err    error
}

// StartCall runs f in the background.
func StartCall(f func() (string, error)) *SDKCall {
	c := &SDKCall{done: make(chan struct{})}
	go func() {
		c.detail, c.err = f()
		close(c.done)
	}()
	return c
}

// Until waits for the next phase to begin, which ends this one, or for the
// call to end first, and returns its error then.
func (c *SDKCall) Until(next *PhaseStart) (string, error) {
	select {
	case <-next.ch:
		return "", nil
	case <-c.done:
		if next.began() {
			return "", nil // a failure in the next phase is that step's
		}
		return "", c.err
	}
}

// Wait waits for the call to end.
func (c *SDKCall) Wait() (string, error) {
	<-c.done
	return c.detail, c.err
}

// run runs the step's action.
func (s Step) run() (string, error) {
	if s.progressAction == nil {
		return s.Action()
	}
	ch := make(chan float64, 100)
	go func() {
		for range ch {
		}
	}()
	return s.progressAction(ch)
}

// stillEvery is how often a step that shows no live progress says it is
// still running; tests shorten it.
var stillEvery = 10 * time.Second

// RunPipeline runs steps one after another, each reported on subject's
// lines: started, still running every stillEvery, and done, with how long
// it took. A step with begins starts its lines when its work begins. A
// step's live progress shows with --progress instead of the still lines.
// The first failure stops the pipeline and is returned, for main to print.
func RunPipeline(ctx context.Context, subject string, steps []Step) error {
	head := console.Bold + console.Safe(subject) + ":" + console.Reset + " "
	cancelled := false // said once for the whole pipeline
	for _, s := range steps {
		// A label can hold a name from outside the CLI: a file's, a
		// secret's.
		label, doneLabel := console.Safe(s.Label), console.Safe(s.Done)
		start := time.Now()
		started := func() { console.AboveLive(func() { fmt.Fprintf(os.Stderr, "%s%s...\n", head, label) }) }
		// A step whose work begins inside its action shows nothing until
		// then; any other step begins now.
		var begins <-chan struct{}
		if s.Begins != nil {
			begins = s.Begins.ch
		} else {
			started()
		}
		waiting := begins != nil

		type outcome struct {
			detail string
			err    error
		}
		done := make(chan outcome, 1)
		go func() {
			detail, err := s.run()
			done <- outcome{detail, err}
		}()

		liveHead := head + label + "..."
		progress := s.Live != nil && ShowProgress
		ticker := time.NewTicker(200 * time.Millisecond)
		interrupted := ctx.Done()
		logged, said := start, start
		var out outcome
	wait:
		for {
			select {
			case <-begins:
				begins, waiting = nil, false
				start = s.Begins.at
				logged, said = start, start
				started()
				s.Begins.show()
			case now := <-ticker.C:
				switch {
				case cancelled, waiting, prompt.LineOpen():
					// A prompt for a PIN keeps its line until it is answered.
				case !progress:
					if now.Sub(said) >= stillEvery {
						said = now
						console.AboveLive(func() {
							fmt.Fprintf(os.Stderr, "%sStill %s... [%s elapsed]\n", head, lowerFirst(label), now.Sub(start).Round(time.Second))
						})
					}
				case console.StderrIsTerminal:
					// Progress redraws in place on a terminal.
					f := s.Live.frame(now)
					width, height := console.Size()
					console.DrawLive(liveLines(liveHead, f, now, width, height, console.LiveCursor))
				case now.Sub(logged) >= progressLogEvery:
					// Redirected, redraws would fill the output with partial
					// lines, so it is a line every progressLogEvery instead.
					logged = now
					f := s.Live.frame(now)
					console.WithLiveCleared(func() {
						fmt.Fprintf(os.Stderr, "%s  %s\n", liveHead, liveStats(f))
					})
				}
			case <-interrupted:
				// Ctrl+C or SIGTERM. The SDK's requests see the cancellation
				// and unwind within moments; say so at once, so the output
				// does not look frozen meanwhile. Once is enough: a closed
				// channel would be ready on every pass.
				interrupted = nil
				if !cancelled {
					cancelled = true
					console.AboveLive(func() {
						prompt.EndLine() // on a line of its own, after a prompt's
						fmt.Fprintf(os.Stderr, "%sInterrupt received. Stopping, please wait...%s\n", console.Yellow, console.Reset)
					})
				}
			case out = <-done:
				break wait
			}
		}
		ticker.Stop()
		console.WithLiveCleared(func() {})

		if out.err != nil {
			if s.Begins != nil {
				s.Begins.show() // no line will come
			}
			return out.err
		}
		if waiting {
			// It ended before its start was seen: both came at once, or the
			// work began without saying so.
			if s.Begins.began() {
				start = s.Begins.at
			}
			started()
			s.Begins.show()
		}
		line := head + doneLabel + " after " + stepDuration(time.Since(start))
		if out.detail != "" {
			line += " [" + console.Safe(out.detail) + "]"
		}
		console.AboveLive(func() { fmt.Fprintln(os.Stderr, line) })
	}
	return nil
}

// progressLogEvery is how often --progress prints a line when stderr is
// not a terminal; tests shorten it.
var progressLogEvery = 5 * time.Second

// stepDuration is how long a step took: milliseconds under a second,
// tenths of a second under a minute, then minutes and seconds.
func stepDuration(d time.Duration) string {
	switch {
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return d.Round(time.Second).String()
}
