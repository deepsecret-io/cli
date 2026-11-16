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

// An owner or admin finds a team among every team of the organization.
// A member finds it among the teams they belong to, through the member
// endpoint, and a team they are not in is not found, like one that does
// not exist (PERMISSIONS.md §6.5).
func TestFindTeam_ListsWhatTheTeamsPermissionAllows(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"success":true,"data":[{"id":"t1","name":"sre","org_id":"o1","members":[{"id":"a1","email":"a@x.test"}]}]}`)
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

	member := &sdkidentity.Member{OrgID: "o1", Permissions: map[string]bool{"teams": false}}
	team, err := findTeam(ctx, c, member, "SRE")
	if err != nil {
		t.Fatalf("member findTeam: %v", err)
	}
	if team.Name != "sre" || len(team.Members) != 1 {
		t.Errorf("member team: %+v", team)
	}
	if got := lastPath(); got != "GET /api/v1/orgs/o1/my-teams" {
		t.Errorf("member request: %s", got)
	}

	_, err = findTeam(ctx, c, member, "finance")
	if err == nil || !strings.Contains(err.Error(), `team "finance" not found`) {
		t.Fatalf("member, team not theirs: %v", err)
	}
	if _, detail := errs.Describe(err); !strings.Contains(detail, "The teams you belong to: sre.") {
		t.Errorf("member detail: %q", detail)
	}

	admin := &sdkidentity.Member{OrgID: "o1", Permissions: map[string]bool{"teams": true}}
	if _, err := findTeam(ctx, c, admin, "sre"); err != nil {
		t.Fatalf("admin findTeam: %v", err)
	}
	if got := lastPath(); got != "GET /api/v1/orgs/o1/teams" {
		t.Errorf("admin request: %s", got)
	}
}

// A team send goes to everyone in the team, the sender included, so a
// team whose only member is the sender sends to the sender alone. A team
// with nobody to send to is refused, naming the way out.
func TestTeamRecipients(t *testing.T) {
	alone := &sdkidentity.Team{Name: "sre", Members: []sdkidentity.TeamMember{{Email: "me@example.com"}}}
	got, err := teamRecipients(alone)
	if err != nil || strings.Join(got, ",") != "me@example.com" {
		t.Fatalf("a team of one: %q, %v", got, err)
	}

	team := &sdkidentity.Team{Name: "eng", Members: []sdkidentity.TeamMember{
		{Email: "me@example.com"}, {Email: ""}, {Email: "alice@example.com"},
	}}
	got, err = teamRecipients(team)
	if err != nil || strings.Join(got, ",") != "me@example.com,alice@example.com" {
		t.Fatalf("a team of two with an empty address: %q, %v", got, err)
	}

	_, err = teamRecipients(&sdkidentity.Team{Name: "empty"})
	summary, detail := errs.Describe(err)
	if err == nil || !strings.Contains(summary, `"empty" has no members to send to`) || !strings.Contains(detail, "leave out --team") {
		t.Fatalf("an empty team: %q, %q", summary, detail)
	}
}
