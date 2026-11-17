package principal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/store"
)

func TestBindingRevocationHTTPInvalidatesOnlyCreatorAgentSubtrees(t *testing.T) {
	for _, operation := range []string{"self", "admin"} {
		for _, auditFailure := range []bool{false, true} {
			name := operation + "/success"
			if auditFailure {
				name = operation + "/audit_failure"
			}
			t.Run(name, func(t *testing.T) {
				ctx := context.Background()
				f := newSelfBindingFixture(t)
				f.authz.StepUp = f.sessions
				if _, err := f.store.Pool.Exec(ctx, `UPDATE members SET binding_policy = 'shared' WHERE id = $1`, f.target.ID); err != nil {
					t.Fatal(err)
				}
				if _, err := f.store.Pool.Exec(ctx, `INSERT INTO users (id, email, email_normalized, password_hash, status)
					VALUES ('usr_binding_peer', 'binding-peer@example.test', 'binding-peer@example.test', 'test-hash', 'active')`); err != nil {
					t.Fatal(err)
				}
				if _, err := f.store.Pool.Exec(ctx, `INSERT INTO user_members (user_id, member_id) VALUES ('usr_binding_peer', $1)`, f.target.ID); err != nil {
					t.Fatal(err)
				}
				if _, err := f.store.Pool.Exec(ctx, `UPDATE members SET binding_policy = 'shared' WHERE id = $1`, f.owner.ID); err != nil {
					t.Fatal(err)
				}
				if _, err := f.store.Pool.Exec(ctx, `INSERT INTO user_members (user_id, member_id) VALUES ('usr_binding_peer', $1)`, f.owner.ID); err != nil {
					t.Fatal(err)
				}
				seedTestInlineGrant(t, f.store, f.spaceID, f.owner.ID, f.target.ID, "auth.members:manage")
				agents := &agent.Service{Store: f.store}
				var branch []agent.Agent
				var keys, refreshes, tokens []string
				ownerID := f.target.ID
				expires := time.Now().Add(30 * time.Minute)
				for _, name := range []string{"binding-parent", "binding-child", "binding-grandchild", "other-creator", "other-member"} {
					creator := ""
					switch name {
					case "binding-parent":
						creator = "usr_principal_actor"
					case "other-creator":
						ownerID, creator = f.target.ID, "usr_binding_peer"
					case "other-member":
						ownerID, creator = f.owner.ID, "usr_principal_actor"
					}
					created, key, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: ownerID, CreatedByUser: creator, Name: name, ExpiresAt: expires})
					if err != nil {
						t.Fatal(err)
					}
					ownerID, expires = created.ID, created.ExpiresAt
					branch = append(branch, created)
					keys = append(keys, key)
					seedTestInlineGrant(t, f.store, f.spaceID, f.owner.ID, created.ID, "auth.members:manage")
					refresh, err := agents.CreateOAuthRefreshCredential(ctx, created.ID, time.Time{})
					if err != nil {
						t.Fatal(err)
					}
					refreshes = append(refreshes, refresh)
					issued, err := f.sessions.CreateAgentAccess(ctx, created.ID, f.spaceID, security.DefaultApplicationAudience)
					if err != nil {
						t.Fatal(err)
					}
					tokens = append(tokens, issued.AccessToken)
				}
				remote, err := store.Open(ctx, f.store.Pool.Config().ConnString())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(remote.Close)
				remoteAuthz := &authorization.Service{Store: remote}
				remoteSessions := &session.Service{Store: remote, Signer: f.sessions.Signer}
				check := func(id string, effect engine.Effect) {
					t.Helper()
					decision, _, err := remoteAuthz.Check(ctx, authorization.CheckRequest{MemberID: id, Permission: "auth.members:manage", ResourceSpace: f.spaceID})
					if err != nil || decision.Effect != effect {
						t.Fatalf("cached authorization: code=%s error=%v want=%s", decision.Code, err, effect)
					}
				}
				for _, item := range branch {
					check(item.ID, engine.Allow)
				}
				var versionsBefore, versionsAfter []int64
				versionQuery := `SELECT array_agg(version ORDER BY id) FROM members WHERE id = ANY($1)`
				ids := make([]string, 0, len(branch))
				for _, item := range branch {
					ids = append(ids, item.ID)
				}
				if err := f.store.Pool.QueryRow(ctx, versionQuery, ids).Scan(&versionsBefore); err != nil {
					t.Fatal(err)
				}
				var policyBefore, policyAfter int64
				if err := f.store.Pool.QueryRow(ctx, `SELECT policy_version FROM spaces WHERE id = $1`, f.spaceID).Scan(&policyBefore); err != nil {
					t.Fatal(err)
				}
				if auditFailure {
					if _, err := f.store.Pool.Exec(ctx, `CREATE FUNCTION reject_binding_audit() RETURNS trigger LANGUAGE plpgsql AS $$
						BEGIN IF NEW.action IN ('member.binding.self_revoke', 'member.binding.revoke') THEN RAISE EXCEPTION 'audit rejected by test'; END IF; RETURN NEW; END; $$;
						CREATE TRIGGER test_reject_binding_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_binding_audit()`); err != nil {
						t.Fatal(err)
					}
				}
				response := httptest.NewRecorder()
				if operation == "self" {
					response = removeOwnBinding(ctx, f)
				} else {
					admin, err := f.sessions.CreateForMember(ctx, "usr_binding_peer", f.owner.ID, nil, "binding-admin", 1)
					if err != nil {
						t.Fatal(err)
					}
					seedStepUpProof(t, f.store, admin.SessionID, "members.bindings.revoke", map[string]any{"space_id": f.spaceID, "member_id": f.target.ID, "user_id": "usr_principal_actor"})
					req := httptest.NewRequest(http.MethodDelete, "/v1/spaces/"+f.spaceID+"/members/"+f.target.ID+"/users/usr_principal_actor", nil)
					req.Header.Set("Authorization", "Bearer "+admin.AccessToken)
					f.handler.ServeHTTP(response, req)
					if auditFailure {
						var proofIntact bool
						if err := f.store.Pool.QueryRow(ctx, `SELECT step_up_expires_at IS NOT NULL FROM sessions WHERE id = $1`, admin.SessionID).Scan(&proofIntact); err != nil || !proofIntact {
							t.Fatalf("failed unbinding consumed step-up: intact=%v error=%v", proofIntact, err)
						}
					}
				}
				wantStatus := http.StatusOK
				if auditFailure {
					wantStatus = http.StatusServiceUnavailable
				}
				if response.Code != wantStatus {
					t.Fatalf("binding revocation status=%d want=%d", response.Code, wantStatus)
				}
				for i, item := range branch {
					affected := i < 3 && !auditFailure
					wantEffect, wantState := engine.Allow, "active"
					if affected {
						wantEffect, wantState = engine.Deny, "suspended"
					}
					check(item.ID, wantEffect)
					var state string
					var revoked bool
					if err := f.store.Pool.QueryRow(ctx, `SELECT status, NOT EXISTS (SELECT 1 FROM agent_credentials WHERE member_id = $1 AND revoked_at IS NULL) FROM members WHERE id = $1`, item.ID).Scan(&state, &revoked); err != nil || state != wantState || revoked != affected {
						t.Fatalf("branch state=%s revoked=%v error=%v want=%s/%v", state, revoked, err, wantState, affected)
					}
					if _, err := agents.AuthenticateKey(ctx, keys[i]); (err != nil) != affected {
						t.Fatal("Agent key validity disagrees with binding revocation")
					}
					if _, active, err := remoteSessions.Introspect(ctx, tokens[i], security.DefaultApplicationAudience); err != nil || active == affected {
						t.Fatalf("second instance token validity: active=%v affected=%v error=%v", active, affected, err)
					}
					if affected {
						if _, _, err := agents.RotateOAuthRefresh(ctx, refreshes[i]); err == nil {
							t.Fatal("revoked OAuth refresh credential remained valid")
						}
					}
				}
				var targetBinding, peerBinding, otherBinding string
				if err := f.store.Pool.QueryRow(ctx, `SELECT
					(SELECT status FROM user_members WHERE user_id = 'usr_principal_actor' AND member_id = $1),
					(SELECT status FROM user_members WHERE user_id = 'usr_binding_peer' AND member_id = $1),
					(SELECT status FROM user_members WHERE user_id = 'usr_principal_actor' AND member_id = $2)`, f.target.ID, f.owner.ID).Scan(&targetBinding, &peerBinding, &otherBinding); err != nil {
					t.Fatal(err)
				}
				wantBinding := "revoked"
				if auditFailure {
					wantBinding = "active"
				}
				if targetBinding != wantBinding || peerBinding != "active" || otherBinding != "active" {
					t.Fatalf("binding isolation failed: target=%s peer=%s other=%s", targetBinding, peerBinding, otherBinding)
				}
				if err := f.store.Pool.QueryRow(ctx, `SELECT policy_version FROM spaces WHERE id = $1`, f.spaceID).Scan(&policyAfter); err != nil {
					t.Fatal(err)
				}
				if err := f.store.Pool.QueryRow(ctx, versionQuery, ids).Scan(&versionsAfter); err != nil {
					t.Fatal(err)
				}
				for i := range versionsBefore {
					if auditFailure && versionsBefore[i] != versionsAfter[i] {
						t.Fatal("audit failure changed an Agent version")
					}
				}
				if auditFailure && policyBefore != policyAfter {
					t.Fatal("audit failure changed the Space policy version")
				}
				var suspensionAudits int
				auditUser, auditActor := "usr_principal_actor", f.target.ID
				if operation == "admin" {
					auditUser, auditActor = "usr_binding_peer", f.owner.ID
				}
				if err := f.store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'agent.binding.suspend' AND member_id = $1
					AND user_id = $5 AND actor_id = $6 AND space_id = $2 AND resource_group_id = $3 AND owner_chain->0->>'member_id' = $4
					AND metadata->>'binding_user_id' = 'usr_principal_actor'`, branch[0].ID, f.spaceID, branch[0].HomeGroupID, f.target.ID, auditUser, auditActor).Scan(&suspensionAudits); err != nil {
					t.Fatal(err)
				}
				if !auditFailure && suspensionAudits != 1 || auditFailure && suspensionAudits != 0 {
					t.Fatalf("binding suspension audit snapshots=%d", suspensionAudits)
				}
				if !auditFailure {
					newKey, err := agents.RotateForUser(ctx, f.target.ID, "usr_binding_peer", branch[0].ID)
					if err != nil {
						t.Fatalf("remaining bound user could not take over root Agent: %v", err)
					}
					if _, err := agents.AuthenticateKey(ctx, newKey); err != nil {
						t.Fatal("takeover credential is not active")
					}
					fresh, err := f.sessions.CreateAgentAccess(ctx, branch[0].ID, f.spaceID, security.DefaultApplicationAudience)
					if err != nil {
						t.Fatal(err)
					}
					if _, active, err := remoteSessions.Introspect(ctx, fresh.AccessToken, security.DefaultApplicationAudience); err != nil || !active {
						t.Fatalf("fresh token after takeover is not valid: active=%v error=%v", active, err)
					}
					for i := range 3 {
						if _, err := agents.AuthenticateKey(ctx, keys[i]); err == nil {
							t.Fatal("takeover resurrected an old credential")
						}
						if _, active, err := remoteSessions.Introspect(ctx, tokens[i], security.DefaultApplicationAudience); err != nil || active {
							t.Fatalf("takeover resurrected an old access token: active=%v error=%v", active, err)
						}
						if _, _, err := agents.RotateOAuthRefresh(ctx, refreshes[i]); err == nil {
							t.Fatal("takeover resurrected an old refresh credential")
						}
					}
					check(branch[1].ID, engine.Deny)
					check(branch[2].ID, engine.Deny)
				}
			})
		}
	}
}
