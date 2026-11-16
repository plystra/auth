package principal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/store"
)

func TestAgentLifecycleHTTPPreservesIndependentBranches(t *testing.T) {
	for _, endpoint := range []string{"stop", "delete", "self-delete", "member-suspend", "member-remove"} {
		for _, actorKind := range []string{"human", "agent"} {
			if endpoint == "self-delete" && actorKind == "human" {
				continue
			}
			t.Run(endpoint+"/"+actorKind, func(t *testing.T) {
				ctx := context.Background()
				st, authz, owner, spaceID, sessions, _ := newPrincipalFixture(t)
				seedTestInlineGrant(t, st, spaceID, owner.ID, owner.ID, "auth.agents:create")
				agents := &agent.Service{Store: st}
				parent, parentKey, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "selected", ExpiresAt: time.Now().Add(time.Hour)})
				if err != nil {
					t.Fatal(err)
				}
				child, childKey, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: parent.ID, Name: "selected-child", ExpiresAt: parent.ExpiresAt})
				if err != nil {
					t.Fatal(err)
				}
				sibling, siblingKey, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "independent", ExpiresAt: parent.ExpiresAt})
				if err != nil {
					t.Fatal(err)
				}
				members := []string{parent.ID, child.ID, sibling.ID}
				for _, id := range members {
					seedTestInlineGrant(t, st, spaceID, owner.ID, id, "auth.members:read")
				}
				for _, permission := range []string{"self:read", "auth.agents:create", "auth.members:manage"} {
					seedTestInlineGrant(t, st, spaceID, owner.ID, parent.ID, permission)
				}
				remoteStore, err := store.Open(ctx, st.Pool.Config().ConnString())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(remoteStore.Close)
				remoteAuthz := &authorization.Service{Store: remoteStore}
				access := make([]string, len(members))
				for i, id := range members {
					issued, err := sessions.CreateAgentAccess(ctx, id, spaceID, security.DefaultApplicationAudience)
					if err != nil {
						t.Fatal(err)
					}
					access[i] = issued.AccessToken
					decision, _, err := remoteAuthz.Check(ctx, authorization.CheckRequest{MemberID: id, Permission: "auth.members:read", ResourceSpace: spaceID})
					if err != nil || decision.Effect != engine.Allow {
						t.Fatalf("initial remote authority: %+v %v", decision, err)
					}
				}
				actorToken := access[0]
				if actorKind == "human" {
					issued, err := sessions.CreateForMember(ctx, "usr_principal_actor", owner.ID, nil, "test", 1)
					if err != nil {
						t.Fatal(err)
					}
					actorToken = issued.AccessToken
				}
				method, path := http.MethodPost, "/v1/me/agents/"+parent.ID+"/stop"
				switch endpoint {
				case "delete":
					method, path = http.MethodDelete, "/v1/me/agents/"+parent.ID
				case "self-delete":
					method, path = http.MethodDelete, "/v1/me/member"
				case "member-suspend":
					path = "/v1/spaces/" + spaceID + "/members/" + parent.ID + "/suspend"
				case "member-remove":
					path = "/v1/spaces/" + spaceID + "/members/" + parent.ID + "/remove"
				}
				mux := http.NewServeMux()
				(&API{Authorization: authz, Agents: agents, Sessions: sessions}).Register(humago.New(mux, route.HumaConfig("Agent subtree test", "1.0.0")))
				handler := route.Middleware(route.Principal, mux)
				req := httptest.NewRequest(method, path, nil)
				req.Header.Set("Authorization", "Bearer "+actorToken)
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, req)
				if response.Code != http.StatusOK {
					t.Fatalf("lifecycle status=%d body=%s", response.Code, response.Body.String())
				}
				for i, id := range members {
					_, active, err := sessions.Introspect(ctx, access[i], security.DefaultApplicationAudience)
					if err != nil || active != (i == 2) {
						t.Fatalf("member %d live token active=%t error=%v", i, active, err)
					}
					decision, _, err := remoteAuthz.Check(ctx, authorization.CheckRequest{MemberID: id, Permission: "auth.members:read", ResourceSpace: spaceID})
					if err != nil || (decision.Effect == engine.Allow) != (i == 2) {
						t.Fatalf("member %d remote authority=%+v error=%v", i, decision, err)
					}
				}
				if _, err := agents.AuthenticateKey(ctx, parentKey); err == nil {
					t.Fatal("selected Agent key remained usable")
				}
				if _, err := agents.AuthenticateKey(ctx, childKey); err == nil {
					t.Fatal("selected subtree credential remained usable")
				}
				if _, err := agents.AuthenticateKey(ctx, siblingKey); err != nil {
					t.Fatalf("independent Agent credential was revoked: %v", err)
				}
				if strings.Contains(endpoint, "delete") || endpoint == "member-remove" {
					if err := authz.SetMemberStatus(ctx, owner.ID, spaceID, parent.ID, "active"); err == nil {
						t.Fatal("member status update revived an Agent tombstone")
					}
				}
			})
		}
	}
}
