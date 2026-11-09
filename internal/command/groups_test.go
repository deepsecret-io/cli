// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package command

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	sdkidentity "github.com/deepsecret-io/deepsecret-go/identity"

	"github.com/deepsecret-io/cli/internal/auth"
	"github.com/deepsecret-io/cli/internal/errs"
)

// An owner or admin finds a group among every group of the organization.
// A member finds it among the groups they belong to, through the member
// endpoint, and a group they are not in is not found, like one that does
// not exist (PERMISSIONS.md §6.5).
func TestFindGroup_ListsWhatTheGroupsPermissionAllows(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"success":true,"data":[{"id":"g1","name":"sre","org_id":"o1","members":[{"id":"a1","email":"a@x.test"}]}]}`)
	}))
	defer srv.Close()
	c, err := auth.NewClient(srv.URL, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	lastPath := func() string {
		mu.Lock()
		defer mu.Unlock()
		return paths[len(paths)-1]
	}

	member := &sdkidentity.Actor{OrgID: "o1", Permissions: map[string]bool{"groups": false}}
	g, err := findGroup(ctx, c, member, "SRE")
	if err != nil {
		t.Fatalf("member findGroup: %v", err)
	}
	if g.Name != "sre" || len(g.Members) != 1 {
		t.Errorf("member group: %+v", g)
	}
	if got := lastPath(); got != "GET /api/v1/orgs/o1/my-groups" {
		t.Errorf("member request: %s", got)
	}

	_, err = findGroup(ctx, c, member, "finance")
	if err == nil || !strings.Contains(err.Error(), `group "finance" not found`) {
		t.Fatalf("member, group not theirs: %v", err)
	}
	if _, detail := errs.Describe(err); !strings.Contains(detail, "The groups you belong to: sre.") {
		t.Errorf("member detail: %q", detail)
	}

	admin := &sdkidentity.Actor{OrgID: "o1", Permissions: map[string]bool{"groups": true}}
	if _, err := findGroup(ctx, c, admin, "sre"); err != nil {
		t.Fatalf("admin findGroup: %v", err)
	}
	if got := lastPath(); got != "GET /api/v1/orgs/o1/groups" {
		t.Errorf("admin request: %s", got)
	}
}
