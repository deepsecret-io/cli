// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import "github.com/deepsecret-io/sdk"

// Client wraps the SDK client for CLI use.
type Client struct {
	*sdk.Client
}

// NewClient creates a new SDK client wrapped for CLI use.
//
// The CLI's rootCtx (cancelled on SIGINT/SIGTERM in main.go) is installed
// onto every client we build so Ctrl+C propagates into in-flight HTTP
// requests instead of waiting for the per-call timeout. rootCtx may be
// nil during very early startup; SetRootContext tolerates that.
func NewClient(baseURL, apiKey string) (*Client, error) {
	c, err := sdk.NewClient(baseURL, apiKey)
	if err != nil {
		return nil, err
	}
	c.SetRootContext(rootCtx)
	return &Client{Client: c}, nil
}
