// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package login

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The API's answer naming the auth URL is read up to a bound, and one
// past it fails instead of being read without end.
func TestReadAuthURLIsBounded(t *testing.T) {
	url, err := readAuthURL(strings.NewReader(`{"data":{"auth_url":"https://accounts.example.com/o"}}`))
	if err != nil || url != "https://accounts.example.com/o" {
		t.Fatalf("url %q, %v", url, err)
	}
	huge := `{"data":{"auth_url":"https://accounts.example.com/o","pad":"` + strings.Repeat("a", maxAuthURLResponse) + `"}}`
	if _, err := readAuthURL(strings.NewReader(huge)); err == nil || !strings.Contains(err.Error(), "over") {
		t.Fatalf("an oversized answer: %v", err)
	}
	if _, err := readAuthURL(strings.NewReader(`{"data":{}}`)); err == nil {
		t.Fatal("an answer without a URL was accepted")
	}
}

// The callback listener refuses a post past its bound, so a local process
// cannot make the CLI buffer an endless body, and still takes a token
// whose state matches.
func TestReceiveTokenIsBounded(t *testing.T) {
	const state = "s3cr3t-state"
	const token = "aGVhZGVy.cGF5bG9hZA.c2ln" // gitleaks:allow (base64 of "header.payload.sig")
	tokens := make(chan string, 1)
	h := receiveToken(state, tokens)

	huge := `{"state":"` + state + `","token":"` + token + `","pad":"` + strings.Repeat("a", maxTokenPost) + `"}`
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest(http.MethodPost, "/receive", strings.NewReader(huge)))
	if !strings.Contains(w.Body.String(), "invalid request") || len(tokens) != 0 {
		t.Fatalf("an oversized post: %q, %d tokens", w.Body.String(), len(tokens))
	}

	w = httptest.NewRecorder()
	h(w, httptest.NewRequest(http.MethodPost, "/receive", strings.NewReader(`{"state":"other","token":"`+token+`"}`)))
	if !strings.Contains(w.Body.String(), "state mismatch") || len(tokens) != 0 {
		t.Fatalf("a post with another state: %q, %d tokens", w.Body.String(), len(tokens))
	}

	w = httptest.NewRecorder()
	h(w, httptest.NewRequest(http.MethodPost, "/receive", strings.NewReader(`{"state":"`+state+`","token":"`+token+`"}`)))
	if !strings.Contains(w.Body.String(), `"ok":true`) || len(tokens) != 1 || <-tokens != token {
		t.Fatalf("a valid post: %q", w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("reply Content-Type %q", ct)
	}
}
