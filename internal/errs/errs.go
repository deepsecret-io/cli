// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package errs gives errors the detail their Error block shows, and reads the
// cause out of file and API errors.
package errs

import (
	"errors"
	"io/fs"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/deepsecret-io/deepsecret-go/apierror"
)

// APICause is the server's answer that err carries, without the steps the
// SDK named on the way to it, for an error that names what the command
// was doing; err itself when the server did not answer.
func APICause(err error) error {
	var ae *apierror.Error
	if errors.As(err, &ae) {
		return ae
	}
	return err
}

// upperFirst is s with its first letter in upper case.
func upperFirst(s string) string {
	r, n := utf8.DecodeRuneInString(s)
	return string(unicode.ToUpper(r)) + s[n:]
}

// detailedError is an error with the detail its Error block shows under
// the summary: what it means, and what to check or do next.
type detailedError struct {
	err    error
	detail string
}

func (e *detailedError) Error() string { return e.err.Error() }

func (e *detailedError) Unwrap() error { return e.err }

// WithDetail gives err a detail for its Error block.
func WithDetail(err error, detail string) error {
	if err == nil {
		return nil
	}
	return &detailedError{err: err, detail: detail}
}

// JoinDetail is detail followed by the detail err carries (WithDetail),
// such as how to finish an interrupted transfer, for an Error block that
// replaces err's own message.
func JoinDetail(detail string, err error) string {
	var d *detailedError
	if !errors.As(err, &d) || d.detail == "" {
		return detail
	}
	if detail == "" {
		return d.detail
	}
	return detail + "\n\n" + d.detail
}

// Describe is err as an Error block: the first line of its message,
// starting with a capital, as the summary; the rest of the message and the
// detail it carries (WithDetail) as the detail.
func Describe(err error) (summary, detail string) {
	first, rest, _ := strings.Cut(strings.TrimSpace(err.Error()), "\n")
	var parts []string
	if rest != "" {
		lines := strings.Split(rest, "\n")
		for i, l := range lines {
			lines[i] = strings.TrimPrefix(l, "  ")
		}
		parts = append(parts, strings.Join(lines, "\n"))
	}
	var d *detailedError
	if errors.As(err, &d) && d.detail != "" {
		parts = append(parts, d.detail)
	}
	return upperFirst(first), strings.Join(parts, "\n\n")
}

// PathCause is what went wrong in a file operation, without the operation
// and the path that *fs.PathError and *os.LinkError put before it, for an
// error that names the file itself.
func PathCause(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	var le *os.LinkError
	if errors.As(err, &le) {
		return le.Err
	}
	return err
}
