// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"os"
	rtdebug "runtime/debug"
	"strings"
	"testing"
)

func TestSDKNote(t *testing.T) {
	cases := []struct {
		deps []*rtdebug.Module
		want string
	}{
		{[]*rtdebug.Module{{Path: sdkModule, Version: "v0.4.0"}}, "sdk v0.4.0"},
		{[]*rtdebug.Module{{Path: sdkModule, Version: "v0.4.0", Replace: &rtdebug.Module{Path: "../sdk"}}}, "sdk v0.4.0 from ../sdk"},
		{[]*rtdebug.Module{{Path: "example.com/other", Version: "v1.0.0"}}, ""},
	}
	for _, c := range cases {
		if got := sdkNote(c.deps); got != c.want {
			t.Errorf("sdkNote = %q, want %q", got, c.want)
		}
	}
}

// If the module moves again, this fails rather than --version silently
// losing the SDK version.
func TestSDKModuleIsRequired(t *testing.T) {
	raw, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "\t"+sdkModule+" ") {
		t.Errorf("go.mod does not require %s", sdkModule)
	}
}
