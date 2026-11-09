// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package auth

import (
	"errors"
	"strings"

	deepsecret "github.com/deepsecret-io/deepsecret-go"

	"github.com/deepsecret-io/cli/internal/config"
	"github.com/deepsecret-io/cli/internal/errs"
	"github.com/deepsecret-io/cli/internal/logging"
	"github.com/deepsecret-io/cli/internal/safefile"
)

// FlagKey is the key given with --api-key, --api-key-file, --api-key-stdin or
// DS_API_KEY, and FlagKeyOrigin names which of them it came from.
var (
	FlagKey       string
	FlagKeyOrigin string
)

// Resolve picks the credential to use, in priority order: the API key
// given with a flag or DS_API_KEY, the login session, then the API key
// saved in the config file. It returns the credential and where it came
// from. The API URL is compiled in (config.APIBaseURL), so it returns no
// URL. A token or config file others may open (safefile.ErrNotPrivate) is
// an error, not a credential to skip: the user must know it is exposed.
func Resolve() (key, source string, err error) {
	if FlagKey != "" {
		return FlagKey, FlagKeyOrigin, nil
	}
	token, tokenErr := config.LoadToken()
	if tokenErr == nil {
		return "bearer:" + token, "login session", nil
	}
	if errors.Is(tokenErr, safefile.ErrNotPrivate) {
		return "", "", tokenErr
	}
	cfg, cfgErr := config.Load()
	if cfgErr == nil && cfg.APIKey != "" {
		return cfg.APIKey, "saved API key", nil
	}
	if errors.Is(cfgErr, safefile.ErrNotPrivate) {
		return "", "", cfgErr
	}
	summary := "not logged in"
	if errors.Is(tokenErr, config.ErrSessionExpired) {
		summary = "your login session expired"
	}
	return "", "", errs.WithDetail(errors.New(summary),
		"Sign in with 'secret login', or save an API key for later commands:\n  secret config --save-api-key --api-key-stdin")
}

// Source is where the credential of the command's client came
// from (Resolve's source), so a request the server refuses with 401
// can name it: "" until NewAuthenticatedClient runs.
var Source string

// Refused is the Error block for a request the server refused
// with 401: the credential from source is not valid, and what to do next
// depends on where it came from. The key itself is never shown.
func Refused(source string) (summary, detail string) {
	const newKey = "create a new key in the DeepSecret app at https://app.deepsecret.io/account/api-keys"
	switch source {
	case "login session":
		return "Your login session has ended", "Sign in again with 'secret login'."
	case "saved API key":
		return "The server refused your saved API key",
			"It is wrong, has expired or was revoked. Sign in with 'secret login' instead, or " + newKey +
				" and save it:\n  secret config --save-api-key --api-key-stdin"
	case "DS_API_KEY":
		return "The server refused the API key in DS_API_KEY",
			"It is wrong, has expired or was revoked. Unset DS_API_KEY to use your login, or " + newKey + "."
	}
	return "The server refused the API key from " + source,
		"It is wrong, has expired or was revoked. Leave out " + source + " to use your login, or " + newKey + "."
}

// NewAuthenticatedClient creates an SDK client pointed at the compiled-in API
// URL using whichever credential source Resolve picks.
func NewAuthenticatedClient() (*deepsecret.Client, error) {
	key, source, err := Resolve()
	if err != nil {
		return nil, err
	}
	Source = source
	logging.Module(logging.Log, "auth").Debug("credentials resolved", "source", source, "api_url", config.APIBaseURL)
	if token, ok := strings.CutPrefix(key, "bearer:"); ok && FlagKey == "" {
		return NewSessionClient(token)
	}
	return NewClient(config.APIBaseURL, key)
}

// NewSessionClient creates a client for a login session's token. The
// session renews its token while in use, and each renewal revokes the
// token it replaces, so every new token is saved for the next command.
func NewSessionClient(token string) (*deepsecret.Client, error) {
	return NewClient(config.APIBaseURL, "bearer:"+token,
		deepsecret.WithSessionStore(deepsecret.SessionStore{Load: config.LoadToken, Save: config.SaveRefreshedToken}))
}
