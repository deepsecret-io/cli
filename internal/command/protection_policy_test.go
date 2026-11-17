// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/deepsecret-io/cli/internal/auth"
	"github.com/deepsecret-io/cli/internal/testutil"
)

// policyServer answers /members/me for an organization whose key
// protection policy is required.
func policyServer(t *testing.T, required bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data any = map[string]any{}
		if r.URL.Path == "/api/v1/members/me" {
			data = map[string]any{
				"member":     map[string]any{"id": "member-1", "email": "ana@example.com"},
				"membership": map[string]any{"org_id": "org-1", "role": "member", "org_kind": "organization", "key_protection_required": required},
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": data})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Before generating, an organization that requires protected keys refuses
// a key pair with no protection, and says which flags make one. A
// protected key pair, or an organization without the policy, passes.
func TestCheckProtectionPolicy(t *testing.T) {
	testutil.SetHome(t, t.TempDir())
	for _, required := range []bool{true, false} {
		c, err := auth.NewClient(policyServer(t, required).URL, "test-key")
		if err != nil {
			t.Fatal(err)
		}
		err = checkProtectionPolicy(context.Background(), c, false)
		if required {
			if err == nil {
				t.Fatal("an unprotected key pair passed an organization that requires protection")
			}
			text := err.Error() + errsDetail(err)
			for _, want := range []string{"requires a protected key pair", "--password", "--security-key", "--kms-arn"} {
				if !strings.Contains(text, want) {
					t.Errorf("refusal %q does not say %q", text, want)
				}
			}
		} else if err != nil {
			t.Errorf("no policy: %v", err)
		}
		if err := checkProtectionPolicy(context.Background(), c, true); err != nil {
			t.Errorf("required %v, protected key pair refused: %v", required, err)
		}
	}
}
