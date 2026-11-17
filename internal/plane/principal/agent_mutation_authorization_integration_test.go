package principal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/member"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
)

func TestAgentLifecycleHTTPRechecksAuthorityAfterWaitingForLocks(t *testing.T) {
	for _, change := range []string{"actor_grant", "owner_grants", "owner_inactive", "binding", "account"} {
		for _, kind := range []string{"human", "agent"} {
			if kind == "human" && (change == "owner_grants" || change == "owner_inactive") || kind == "agent" && (change == "binding" || change == "account") {
				continue
			}
			for _, operation := range []string{"create", "rotate", "stop", "delete", "remove_self"} {
				if kind == "human" && operation == "remove_self" {
					continue
				}
				t.Run(change+"/"+kind+"/"+operation, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()
					f := newGroupRemovalFixture(t)
					seedTestInlineGrant(t, f.store, f.spaceID, f.owner.ID, f.owner.ID, "auth.agents:create")
					agents := &agent.Service{Store: f.store, StepUp: f.sessions}
					parent, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: f.owner.ID, Name: "lifecycle-parent", ExpiresAt: time.Now().Add(time.Hour)})
					if err != nil {
						t.Fatal(err)
					}
					child, key, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: parent.ID, Name: "lifecycle-child", ExpiresAt: parent.ExpiresAt})
					if err != nil {
						t.Fatal(err)
					}
					actorID, grantID, permission, targetID := parent.ID, "grt_agent_mutation_actor", "auth.agents:create", child.ID
					if kind == "human" {
						actorID = f.owner.ID
						if _, err := f.store.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now()
					WHERE grantee_member_id = $1 AND permission_keys ? 'auth.agents:create'`, actorID); err != nil {
							t.Fatal(err)
						}
					}
					if operation == "remove_self" {
						actorID, permission = child.ID, "self:read"
					}
					if _, err := f.store.Pool.Exec(ctx, `INSERT INTO authorization_grants
				(id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
				VALUES ($1, $2, '["auth.agents:create", "self:read"]', $3, 'space', $2, $4)`, grantID, f.spaceID, actorID, f.owner.ID); err != nil {
						t.Fatal(err)
					}
					if operation == "remove_self" {
						seedTestInlineGrant(t, f.store, f.spaceID, f.owner.ID, parent.ID, "self:read")
					}
					var ownerGrants []string
					if err := f.store.Pool.QueryRow(ctx, `SELECT array_agg(id) FROM authorization_grants WHERE grantee_member_id = $1 AND revoked_at IS NULL`, f.owner.ID).Scan(&ownerGrants); err != nil {
						t.Fatal(err)
					}
					token, sessionID := f.token, ""
					if kind == "agent" {
						issued, err := f.sessions.CreateAgentAccess(ctx, actorID, f.spaceID, security.DefaultApplicationAudience)
						if err != nil {
							t.Fatal(err)
						}
						token = issued.AccessToken
					} else {
						claims, err := f.sessions.VerifyAccess(token)
						if err != nil {
							t.Fatal(err)
						}
						sessionID = claims.SessionID
					}
					mux := http.NewServeMux()
					(&API{Authorization: f.authz, Sessions: f.sessions, Agents: agents}).Register(humago.New(mux, route.HumaConfig("Agent mutation consistency", "1.0.0")))
					handler := route.Middleware(route.Principal, mux)
					method, path, body := http.MethodPost, "/v1/me/agents/"+child.ID+"/"+operation, ""
					switch operation {
					case "create":
						targetID, path = actorID, "/v1/me/agents"
						encoded, _ := json.Marshal(map[string]any{"name": "blocked-child", "expires_at": parent.ExpiresAt.Add(-time.Minute)})
						body = string(encoded)
					case "delete":
						method, path = http.MethodDelete, "/v1/me/agents/"+child.ID
					case "remove_self":
						method, path = http.MethodDelete, "/v1/me/member"
					}
					if kind == "human" {
						switch operation {
						case "create":
							seedStepUpProof(t, f.store, sessionID, "me.agents.create", map[string]any{"name": "blocked-child", "expires_at": parent.ExpiresAt.Add(-time.Minute), "source": ""})
						case "rotate":
							seedStepUpProof(t, f.store, sessionID, "me.agents.rotate", map[string]any{"agent_id": child.ID})
						}
					}
					var membersBefore, credentialsBefore int
					if err := f.store.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM members), (SELECT count(*) FROM agent_credentials)`).Scan(&membersBefore, &credentialsBefore); err != nil {
						t.Fatal(err)
					}
					locked, revoke := make(chan struct{}), make(chan struct{})
					writer := make(chan error, 1)
					go func() {
						writer <- f.store.InTx(ctx, func(q *db.Queries) error {
							if err := member.LockChainsTx(ctx, q, actorID, targetID); err != nil {
								return err
							}
							close(locked)
							select {
							case <-revoke:
							case <-ctx.Done():
								return ctx.Err()
							}
							switch change {
							case "owner_grants":
								for _, id := range ownerGrants {
									if err := q.RevokeGrant(ctx, db.RevokeGrantParams{ID: id}); err != nil {
										return err
									}
								}
								return nil
							case "owner_inactive":
								return q.SetMemberStatus(ctx, db.SetMemberStatusParams{ID: f.owner.ID, SpaceID: f.spaceID, Status: "suspended"})
							case "binding":
								return q.RevokeUserMember(ctx, db.RevokeUserMemberParams{UserID: "usr_principal_actor", MemberID: actorID})
							case "account":
								return q.SetUserStatus(ctx, db.SetUserStatusParams{ID: "usr_principal_actor", Status: "disabled"})
							default:
								return q.RevokeGrant(ctx, db.RevokeGrantParams{ID: grantID})
							}
						})
					}()
					select {
					case <-locked:
					case err := <-writer:
						t.Fatalf("could not establish authorization barrier: %v", err)
					}
					response := make(chan *httptest.ResponseRecorder, 1)
					go func() {
						request := httptest.NewRequest(method, path, strings.NewReader(body)).WithContext(ctx)
						request.Header.Set("Authorization", "Bearer "+token)
						request.Header.Set("Content-Type", "application/json")
						out := httptest.NewRecorder()
						handler.ServeHTTP(out, request)
						response <- out
					}()
					for {
						var waiting bool
						if err := f.store.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname = current_database()
					AND wait_event_type = 'Lock' AND query LIKE '%members%FOR UPDATE%')`).Scan(&waiting); err != nil {
							t.Fatal(err)
						}
						if waiting {
							break
						}
						select {
						case out := <-response:
							t.Fatalf("lifecycle request did not reach mutation lock: status=%d", out.Code)
						case <-ctx.Done():
							t.Fatal(ctx.Err())
						case <-time.After(10 * time.Millisecond):
						}
					}
					close(revoke)
					if err := <-writer; err != nil {
						t.Fatal(err)
					}
					out := <-response
					if change == "binding" || change == "account" {
						if out.Code != http.StatusUnauthorized || !strings.Contains(out.Body.String(), "UNAUTHENTICATED") {
							t.Fatalf("lifecycle mutation retained revoked user authority: status=%d", out.Code)
						}
					} else {
						decision, _, err := f.authz.Check(ctx, authorization.CheckRequest{MemberID: actorID, Permission: permission, ResourceSpace: f.spaceID, ResourceOwner: targetID})
						if err != nil || decision.Effect != engine.Deny || out.Code != http.StatusForbidden || !strings.Contains(out.Body.String(), decision.Code) {
							t.Fatalf("lifecycle mutation used obsolete authority: check=%s error=%v status=%d", decision.Code, err, out.Code)
						}
						if change == "owner_grants" && decision.Code != "OWNER_ENVELOPE_EXCLUDED" || change == "owner_inactive" && decision.Code != "OWNER_INACTIVE" {
							t.Fatalf("incorrect owner denial: %s", decision.Code)
						}
					}
					var membersAfter, credentialsAfter, mutationAudits int
					var status string
					if err := f.store.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM members), (SELECT count(*) FROM agent_credentials),
				(SELECT status FROM members WHERE id = $1),
				(SELECT count(*) FROM audit_logs WHERE actor_id = $2 AND action IN ('agent.create', 'agent.stop', 'agent.delete', 'agent.credential.rotate'))`, child.ID, actorID).
						Scan(&membersAfter, &credentialsAfter, &status, &mutationAudits); err != nil {
						t.Fatal(err)
					}
					// The parent's provisioning of the fixture child is the only initial
					// audit with this actor. A denied request must not add another one.
					wantAudits := 1
					if operation == "remove_self" {
						wantAudits = 0
					}
					if membersAfter != membersBefore || credentialsAfter != credentialsBefore || status != "active" || mutationAudits != wantAudits {
						t.Fatalf("denied lifecycle write changed state: members=%d/%d credentials=%d/%d status=%s audits=%d", membersAfter, membersBefore, credentialsAfter, credentialsBefore, status, mutationAudits)
					}
					var revoked bool
					if err := f.store.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM agent_credentials WHERE member_id = $1 AND revoked_at IS NOT NULL)`, child.ID).Scan(&revoked); err != nil || revoked {
						t.Fatalf("denied lifecycle mutation revoked a credential: revoked=%v error=%v", revoked, err)
					}
					if _, err := agents.AuthenticateKey(ctx, key); err != nil && change != "owner_inactive" {
						t.Fatal("denied lifecycle operation revoked the existing credential")
					}
					if kind == "human" && (operation == "create" || operation == "rotate") {
						var proofIntact bool
						if err := f.store.Pool.QueryRow(ctx, `SELECT step_up_expires_at IS NOT NULL FROM sessions WHERE id = $1`, sessionID).Scan(&proofIntact); err != nil || !proofIntact {
							t.Fatalf("denied lifecycle mutation consumed step-up: intact=%v error=%v", proofIntact, err)
						}
					}
				})
			}
		}
	}
}

func TestAgentLifecycleHTTPMatchesCheckForTargetAndPolicy(t *testing.T) {
	for _, policy := range []string{"target_group", "outside_group", "disabled", "deprecated", "principal_kinds", "envelope"} {
		for _, operation := range []string{"create", "rotate", "stop", "delete", "remove_self"} {
			t.Run(policy+"/"+operation, func(t *testing.T) {
				ctx := context.Background()
				f := newGroupRemovalFixture(t)
				seedTestInlineGrant(t, f.store, f.spaceID, f.owner.ID, f.owner.ID, "auth.agents:create")
				agents := &agent.Service{Store: f.store}
				parent, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: f.owner.ID, Name: "policy-parent", ExpiresAt: time.Now().Add(time.Hour)})
				if err != nil {
					t.Fatal(err)
				}
				child, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: parent.ID, Name: "policy-child", ExpiresAt: parent.ExpiresAt})
				if err != nil {
					t.Fatal(err)
				}
				permission := "auth.agents:create"
				if operation == "remove_self" {
					permission = "self:read"
				}
				seedTestInlineGrant(t, f.store, f.spaceID, f.owner.ID, parent.ID, permission)
				switch policy {
				case "target_group", "outside_group":
					anchor := parent.HomeGroupID
					if policy == "outside_group" {
						anchor = "grp_remove_a"
					}
					_, err = f.store.Pool.Exec(ctx, `UPDATE authorization_grants SET scope = 'group_tree', anchor_space_id = NULL, anchor_group_id = $2 WHERE grantee_member_id = $1`, parent.ID, anchor)
				case "disabled", "deprecated":
					_, err = f.store.Pool.Exec(ctx, `UPDATE permissions SET status = $1 WHERE key = $2`, policy, permission)
				case "principal_kinds":
					_, err = f.store.Pool.Exec(ctx, `UPDATE permissions SET principal_kinds = '["human"]' WHERE key = $1`, permission)
				case "envelope":
					_, err = f.store.Pool.Exec(ctx, `INSERT INTO space_envelopes (space_id) VALUES ($1)`, f.spaceID)
				}
				if err != nil {
					t.Fatal(err)
				}
				tokens, err := f.sessions.CreateAgentAccess(ctx, parent.ID, f.spaceID, security.DefaultApplicationAudience)
				if err != nil {
					t.Fatal(err)
				}
				method, path, body := http.MethodPost, "/v1/me/agents/"+child.ID+"/"+operation, ""
				targetID, groupID := child.ID, child.HomeGroupID
				switch operation {
				case "create":
					path, targetID, groupID = "/v1/me/agents", parent.ID, parent.HomeGroupID
					encoded, _ := json.Marshal(map[string]any{"name": "policy-grandchild", "expires_at": parent.ExpiresAt.Add(-time.Minute)})
					body = string(encoded)
				case "delete":
					method, path = http.MethodDelete, "/v1/me/agents/"+child.ID
				case "remove_self":
					method, path, targetID, groupID = http.MethodDelete, "/v1/me/member", parent.ID, parent.HomeGroupID
				}
				decision, _, err := f.authz.Check(ctx, authorization.CheckRequest{
					MemberID: parent.ID, Permission: permission, ResourceSpace: f.spaceID, ResourceGroup: groupID, ResourceOwner: targetID,
				})
				if err != nil {
					t.Fatal(err)
				}
				wantAllow := policy == "target_group" || policy == "deprecated"
				if (decision.Effect == engine.Allow) != wantAllow {
					t.Fatalf("unexpected check decision: %s", decision.Code)
				}
				mux := http.NewServeMux()
				(&API{Authorization: f.authz, Sessions: f.sessions, Agents: agents}).Register(humago.New(mux, route.HumaConfig("Agent policy", "1.0.0")))
				request := httptest.NewRequest(method, path, strings.NewReader(body))
				request.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
				request.Header.Set("Content-Type", "application/json")
				out := httptest.NewRecorder()
				route.Middleware(route.Principal, mux).ServeHTTP(out, request)
				if wantAllow {
					if out.Code != http.StatusOK {
						t.Fatalf("allowed lifecycle request failed: status=%d", out.Code)
					}
				} else if out.Code != http.StatusForbidden || !strings.Contains(out.Body.String(), decision.Code) {
					t.Fatalf("management and check differ: check=%s status=%d", decision.Code, out.Code)
				}
			})
		}
	}
}

func TestAgentLifecycleRoutesDeclareTransactionalHumanAgentChecks(t *testing.T) {
	(&API{}).Register(humago.New(http.NewServeMux(), route.HumaConfig("Agent route declarations", "1.0.0")))
	wanted := map[string]string{
		"me.agents.create": "auth.agents:create", "me.agents.rotate": "auth.agents:create",
		"me.agents.stop": "auth.agents:create", "me.agents.delete": "auth.agents:create", "auth.me_member_remove": "self:read",
	}
	for _, spec := range route.Specs() {
		permission, ok := wanted[spec.Name]
		if !ok {
			continue
		}
		if spec.Permission != permission || !spec.AuthoritativeCheck || len(spec.Subjects) != 1 || spec.Subjects[0] != route.HumanAgent {
			t.Fatalf("Agent lifecycle declaration is incomplete: %+v", spec)
		}
		if spec.StepUp != (spec.Name == "me.agents.create" || spec.Name == "me.agents.rotate") {
			t.Fatalf("Agent lifecycle step-up declaration is incorrect: %+v", spec)
		}
		delete(wanted, spec.Name)
	}
	if len(wanted) != 0 {
		t.Fatalf("missing Agent lifecycle declarations: %v", wanted)
	}
}
