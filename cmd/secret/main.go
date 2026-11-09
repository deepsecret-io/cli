// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Command secret is the DeepSecret CLI: end-to-end encrypted secrets from the
// terminal.
package main

import (
	"os"

	"github.com/deepsecret-io/cli/internal/command"
)

// version is a release's vMAJOR.MINOR.PATCH, set from the tag by the
// release build (.goreleaser.yaml); every other build is "dev".
var version = "dev"

func main() {
	os.Exit(command.Execute(version))
}
