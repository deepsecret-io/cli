// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

// apiBaseURL is the production DeepSecret API endpoint, baked in at compile
// time. The CLI deliberately does NOT read the URL from --api-url, env vars,
// or config so a tampered config file can't redirect traffic to an
// attacker-controlled host. To target a different deployment, build a fork
// with this constant changed and verify the binary's checksum out-of-band.
const apiBaseURL = "http://localhost:80"
