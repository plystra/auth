package principal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/plystra/auth/internal/agent"
)

func TestMemberRevocationAuditHTTPPreservesTargetAndActorChains(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"human", "agent"} {
		for _, name := range []string{"binding_revoke", "member_suspend", "member_resume", "member_remove"} {
			t.Run(kind+"/"+name, func(t *testing.T) {
				t.Parallel()
				ctx := context.Background()
				f, op := newMemberIdentityOperation(t, kind, name)
				reader, err := f.authz.CreateMember(ctx, f.ownerID, "usr_principal_actor", f.spaceID, "Revocation auditor", "human", "single")
				if err != nil {
					t.Fatal(err)
				}
				seedAuditGroupReader(t, f.store, f.spaceID, f.ownerID, reader.ID, f.fromID)
				readerTokens, err := f.sessions.CreateForMember(ctx, "usr_principal_actor", reader.ID, nil, "test", 1)
				if err != nil {
					t.Fatal(err)
				}
				out := memberIdentityRequest(t, ctx, f, op)
				if out.Code != http.StatusOK {
					t.Fatalf("member revocation failed: status=%d", out.Code)
				}
				action, permission := "member.status.update", "auth.members:manage"
				if name == "binding_revoke" {
					action, permission = "member.binding.revoke", "auth.bindings:manage"
				}
				path := "/v1/spaces/" + f.spaceID + "/audit-logs?request_id=req_member_identity&action=" + action
				page := decodeAuditPage(t, getAuditHTTP(f.handler, f.ownerToken, path+"&member_id="+f.ownerID))
				if len(page.Body.Data) != 1 {
					t.Fatalf("revocation has %d queryable events, want 1", len(page.Body.Data))
				}
				event := page.Body.Data[0]
				if event.ActorID != f.actorID || event.ActorType != "member" || event.MemberID != f.actorID || event.MemberType != kind ||
					event.UserID != f.userID || event.CredentialType != f.credentialType || event.Plane != "principal" || event.Outcome != "success" ||
					event.SpaceID != f.spaceID || event.ResourceType != "member" || event.ResourceID != f.holderID || event.ResourceGroupID != f.fromID ||
					event.PermissionKey != permission || event.PolicyVersion <= 0 || event.RequestID != "req_member_identity" {
					t.Fatal("revocation audit confused the acting identity with the affected member")
				}
				var version int64
				if err := f.store.Pool.QueryRow(ctx, `SELECT policy_version FROM spaces WHERE id = $1`, f.spaceID).Scan(&version); err != nil || version != event.PolicyVersion {
					t.Fatal("revocation audit did not preserve the committed policy version")
				}
				var ownerIDs []string
				for index, owner := range event.OwnerChain {
					ownerIDs = append(ownerIDs, owner.MemberID)
					wantType := "agent"
					if index == len(event.OwnerChain)-1 {
						wantType = "human"
					}
					if owner.SpaceID != f.spaceID || owner.MemberType != wantType {
						t.Fatal("revocation audit has incorrect owner identity facts")
					}
				}
				if !slices.Equal(ownerIDs, f.owners) {
					t.Fatal("revocation audit lost the acting owner chain")
				}
				var metadata map[string]any
				if err := json.Unmarshal(event.Metadata, &metadata); err != nil || metadata["owner_chain_complete"] != true {
					t.Fatal("revocation audit owner chain is incomplete")
				}
				if name == "binding_revoke" {
					if metadata["binding_user_id"] != "usr_member_recipient" {
						t.Fatal("binding revocation confused the acting user with the bound account")
					}
				} else {
					previous, current := "active", "suspended"
					switch name {
					case "member_resume":
						previous, current = "suspended", "active"
					case "member_remove":
						current = "removed"
					}
					if metadata["previous_status"] != previous || metadata["status"] != current || metadata["type"] != "human" {
						t.Fatal("member status audit omitted the affected type or before and after status")
					}
				}
				encoded, err := json.Marshal(event)
				if err != nil {
					t.Fatal(err)
				}
				for _, token := range append(slices.Clone(f.credentials), "member-recipient@example.test", "test-password-hash") {
					if strings.Contains(string(encoded), token) {
						t.Fatal("revocation audit exposed credentials or private labels")
					}
				}
				groupPage := decodeAuditPage(t, getAuditHTTP(f.handler, readerTokens.AccessToken, path))
				if len(groupPage.Body.Data) != 1 || !cmp.Equal(groupPage.Body.Data[0], event) {
					t.Fatal("group auditor could not read the event at the affected member's position")
				}
				if kind == "agent" {
					if err := (&agent.Service{Store: f.store}).Delete(ctx, f.ownerID, f.parentID); err != nil {
						t.Fatal(err)
					}
					page = decodeAuditPage(t, getAuditHTTP(f.handler, f.ownerToken, path+"&member_id="+f.ownerID))
					if len(page.Body.Data) != 1 || !cmp.Equal(page.Body.Data[0], event) {
						t.Fatal("Agent tombstones changed the revocation audit snapshot")
					}
				}
			})
		}
	}
}

func TestMemberRevocationAuditHTTPFailureRollsBackStateAndProofs(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"human", "agent"} {
		for _, name := range []string{"binding_revoke", "member_suspend", "member_resume", "member_remove"} {
			t.Run(kind+"/"+name, func(t *testing.T) {
				t.Parallel()
				ctx := context.Background()
				f, op := newMemberIdentityOperation(t, kind, name)
				if name != "binding_revoke" {
					if _, err := f.store.Pool.Exec(ctx, `UPDATE members SET status = 'active' WHERE id = $1`, f.holderID); err != nil {
						t.Fatal(err)
					}
					if err := f.authz.BindUser(ctx, f.ownerID, f.spaceID, f.holderID, "usr_member_recipient"); err != nil {
						t.Fatal(err)
					}
					if _, err := f.sessions.CreateForMember(ctx, "usr_member_recipient", f.holderID, nil, "recipient", 1); err != nil {
						t.Fatal(err)
					}
					if name == "member_resume" {
						if _, err := f.store.Pool.Exec(ctx, `UPDATE members SET status = 'suspended' WHERE id = $1`, f.holderID); err != nil {
							t.Fatal(err)
						}
					}
				}
				state := func() string {
					t.Helper()
					var versions string
					if err := f.store.Pool.QueryRow(ctx, `SELECT jsonb_agg(jsonb_build_array(id, policy_version) ORDER BY id)::text FROM spaces`).Scan(&versions); err != nil {
						t.Fatal(err)
					}
					return memberIdentityState(t, ctx, f) + versions
				}
				action := "member.status.update"
				if name == "binding_revoke" {
					action = "member.binding.revoke"
				}
				if _, err := f.store.Pool.Exec(ctx, `CREATE FUNCTION reject_member_revocation_audit() RETURNS trigger LANGUAGE plpgsql AS $$
					BEGIN IF NEW.request_id = 'req_member_identity' AND NEW.action = TG_ARGV[0] THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END; $$`); err != nil {
					t.Fatal(err)
				}
				if _, err := f.store.Pool.Exec(ctx, fmt.Sprintf(`CREATE TRIGGER reject_member_revocation_audit BEFORE INSERT ON audit_logs
					FOR EACH ROW EXECUTE FUNCTION reject_member_revocation_audit('%s')`, action)); err != nil {
					t.Fatal(err)
				}
				before := state()
				out := memberIdentityRequest(t, ctx, f, op)
				if out.Code != http.StatusServiceUnavailable || !strings.Contains(out.Body.String(), `"code":"UNAVAILABLE"`) {
					t.Fatalf("revocation ignored audit failure: status=%d", out.Code)
				}
				if state() != before {
					t.Fatal("failed revocation changed state, sessions, policy versions, audit, approval, or step-up")
				}
				if _, err := f.store.Pool.Exec(ctx, `DROP TRIGGER reject_member_revocation_audit ON audit_logs`); err != nil {
					t.Fatal(err)
				}
				if out = memberIdentityRequest(t, ctx, f, op); out.Code != http.StatusOK {
					t.Fatalf("original revocation proof could not retry: status=%d", out.Code)
				}
				page := decodeAuditPage(t, getAuditHTTP(f.handler, f.ownerToken,
					"/v1/spaces/"+f.spaceID+"/audit-logs?request_id=req_member_identity&action="+action))
				if len(page.Body.Data) != 1 {
					t.Fatal("retried revocation did not commit exactly one success event")
				}
			})
		}
	}
}

func TestMemberRevocationAuditHTTPUsesSpaceForAmbiguousPositions(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"binding_revoke", "member_suspend", "member_resume", "member_remove"} {
		for _, position := range []string{"no_groups", "multiple_groups"} {
			t.Run(name+"/"+position, func(t *testing.T) {
				t.Parallel()
				ctx := context.Background()
				f, op := newMemberIdentityOperation(t, "human", name)
				var err error
				if position == "no_groups" {
					err = f.authz.RemoveMemberFromGroup(ctx, f.ownerID, f.spaceID, f.fromID, f.holderID)
				} else {
					_, err = f.store.Pool.Exec(ctx, `INSERT INTO group_members (group_id, member_id) VALUES ($1, $2)`, f.toID, f.holderID)
				}
				if err != nil {
					t.Fatal(err)
				}
				if out := memberIdentityRequest(t, ctx, f, op); out.Code != http.StatusOK {
					t.Fatalf("revocation at ambiguous position failed: status=%d", out.Code)
				}
				action := "member.status.update"
				if name == "binding_revoke" {
					action = "member.binding.revoke"
				}
				path := "/v1/spaces/" + f.spaceID + "/audit-logs?request_id=req_member_identity&action=" + action
				page := decodeAuditPage(t, getAuditHTTP(f.handler, f.ownerToken, path))
				if len(page.Body.Data) != 1 || page.Body.Data[0].ResourceGroupID != "" || page.Body.Data[0].ResourceID != f.holderID {
					t.Fatal("revocation at an ambiguous position did not use the Space audit boundary")
				}
				if _, err := f.store.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, f.ownerID); err != nil {
					t.Fatal(err)
				}
				seedAuditGroupReader(t, f.store, f.spaceID, f.ownerID, f.ownerID, f.fromID)
				if page = decodeAuditPage(t, getAuditHTTP(f.handler, f.ownerToken, path)); len(page.Body.Data) != 0 {
					t.Fatal("group auditor read a Space-wide revocation event")
				}
			})
		}
	}
}

func TestHumanSelfUnbindingHTTPAuditIsAtomicAndQueryable(t *testing.T) {
	t.Parallel()
	for _, position := range []string{"single_group", "no_groups", "multiple_groups"} {
		for _, auditFailure := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/failure=%t", position, auditFailure), func(t *testing.T) {
				t.Parallel()
				ctx := context.Background()
				f := newSelfBindingFixture(t)
				if position != "single_group" {
					if _, err := f.store.Pool.Exec(ctx, `UPDATE authorization_grants SET scope = 'space', anchor_group_id = NULL, anchor_space_id = $1
						WHERE id = 'grt_self_unbind'`, f.spaceID); err != nil {
						t.Fatal(err)
					}
					if position == "no_groups" {
						if _, err := f.store.Pool.Exec(ctx, `DELETE FROM group_members WHERE member_id = $1`, f.target.ID); err != nil {
							t.Fatal(err)
						}
					} else if _, err := f.store.Pool.Exec(ctx, `INSERT INTO group_members (group_id, member_id) VALUES ('grp_remove_b', $1)`, f.target.ID); err != nil {
						t.Fatal(err)
					}
				}
				reader, err := f.sessions.CreateForMember(ctx, "usr_principal_actor", f.owner.ID, nil, "auditor", 1)
				if err != nil {
					t.Fatal(err)
				}
				var versionBefore, versionAfter int64
				if err := f.store.Pool.QueryRow(ctx, `SELECT policy_version FROM spaces WHERE id = $1`, f.spaceID).Scan(&versionBefore); err != nil {
					t.Fatal(err)
				}
				if auditFailure {
					if _, err := f.store.Pool.Exec(ctx, `CREATE FUNCTION reject_self_revocation_audit() RETURNS trigger LANGUAGE plpgsql AS $$
						BEGIN IF NEW.action = 'member.binding.self_revoke' THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END; $$;
						CREATE TRIGGER reject_self_revocation_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_self_revocation_audit()`); err != nil {
						t.Fatal(err)
					}
				}
				request := func() *httptest.ResponseRecorder {
					req := httptest.NewRequest(http.MethodDelete, "/v1/me/member", nil)
					req.Header.Set("Authorization", "Bearer "+f.token)
					req.Header.Set("X-Request-ID", "req_self_revocation_audit")
					out := httptest.NewRecorder()
					f.handler.ServeHTTP(out, req)
					return out
				}
				out := request()
				path := "/v1/spaces/" + f.spaceID + "/audit-logs?request_id=req_self_revocation_audit&action=member.binding.self_revoke&member_id=" + f.target.ID
				if auditFailure {
					if out.Code != http.StatusServiceUnavailable {
						t.Fatalf("self-unbinding ignored audit failure: status=%d", out.Code)
					}
					assertSelfBindingUnchanged(t, f, "active")
					if err := f.store.Pool.QueryRow(ctx, `SELECT policy_version FROM spaces WHERE id = $1`, f.spaceID).Scan(&versionAfter); err != nil || versionAfter != versionBefore {
						t.Fatal("failed self-unbinding changed the policy version")
					}
					if page := decodeAuditPage(t, getAuditHTTP(f.handler, reader.AccessToken, path)); len(page.Body.Data) != 0 {
						t.Fatal("failed self-unbinding left a success audit")
					}
					if _, err := f.store.Pool.Exec(ctx, `DROP TRIGGER reject_self_revocation_audit ON audit_logs`); err != nil {
						t.Fatal(err)
					}
					out = request()
				}
				if out.Code != http.StatusOK {
					t.Fatalf("self-unbinding failed: status=%d", out.Code)
				}
				page := decodeAuditPage(t, getAuditHTTP(f.handler, reader.AccessToken, path))
				if len(page.Body.Data) != 1 {
					t.Fatal("self-unbinding did not produce one queryable event")
				}
				event := page.Body.Data[0]
				groupID := ""
				if position == "single_group" {
					groupID = "grp_remove_a"
				}
				if event.ActorID != f.target.ID || event.MemberID != f.target.ID || event.MemberType != "human" || event.UserID != "usr_principal_actor" ||
					event.CredentialType != "user_access_token" || event.Plane != "principal" || event.ResourceType != "member" || event.ResourceID != f.target.ID ||
					event.ResourceGroupID != groupID || event.SpaceID != f.spaceID || event.PermissionKey != "self:read" || len(event.OwnerChain) != 0 {
					t.Fatal("self-unbinding audit omitted its authenticated identity or actual target")
				}
				if err := f.store.Pool.QueryRow(ctx, `SELECT policy_version FROM spaces WHERE id = $1`, f.spaceID).Scan(&versionAfter); err != nil ||
					event.PolicyVersion != versionAfter || versionAfter <= versionBefore {
					t.Fatal("self-unbinding audit omitted the committed policy version")
				}
				if strings.Contains(string(event.Metadata), f.token) {
					t.Fatal("self-unbinding audit exposed its credential")
				}
			})
		}
	}
}

func TestMemberStatusAuditHTTPPreservesAgentTargetAndAtomicSubtree(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"human", "agent"} {
		for _, status := range []string{"suspended", "removed"} {
			for _, auditFailure := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/failure=%t", kind, status, auditFailure), func(t *testing.T) {
					t.Parallel()
					ctx := context.Background()
					f, op := newMemberIdentityOperation(t, kind, "member_suspend")
					agents := &agent.Service{Store: f.store}
					expiresAt := time.Now().Add(time.Hour).Truncate(time.Second)
					target, targetKey, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: f.holderID, Name: "Managed Agent", ExpiresAt: expiresAt})
					if err != nil {
						t.Fatal(err)
					}
					child, childKey, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: target.ID, Name: "Managed child", ExpiresAt: expiresAt.Add(-time.Minute)})
					if err != nil {
						t.Fatal(err)
					}
					peer, peerKey, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: f.holderID, Name: "Independent sibling", ExpiresAt: expiresAt})
					if err != nil {
						t.Fatal(err)
					}
					suffix := "suspend"
					if status == "removed" {
						suffix = "remove"
					}
					op.path = "/v1/spaces/" + f.spaceID + "/members/" + target.ID + "/" + suffix
					state := func() string {
						t.Helper()
						var extra string
						if err := f.store.Pool.QueryRow(ctx, `SELECT jsonb_build_object(
							'groups', (SELECT jsonb_agg(to_jsonb(g) ORDER BY id) FROM groups g),
							'credentials', (SELECT jsonb_agg(to_jsonb(c) ORDER BY id) FROM agent_credentials c),
							'versions', (SELECT jsonb_agg(jsonb_build_array(id, policy_version) ORDER BY id) FROM spaces))::text`).Scan(&extra); err != nil {
							t.Fatal(err)
						}
						return memberIdentityState(t, ctx, f) + extra
					}
					before := state()
					var version int64
					if err := f.store.Pool.QueryRow(ctx, `SELECT policy_version FROM spaces WHERE id = $1`, f.spaceID).Scan(&version); err != nil {
						t.Fatal(err)
					}
					if auditFailure {
						if _, err := f.store.Pool.Exec(ctx, `CREATE FUNCTION reject_agent_status_audit() RETURNS trigger LANGUAGE plpgsql AS $$
							BEGIN IF NEW.action = 'member.status.update' THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END; $$;
							CREATE TRIGGER reject_agent_status_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_agent_status_audit()`); err != nil {
							t.Fatal(err)
						}
						if out := memberIdentityRequest(t, ctx, f, op); out.Code != http.StatusServiceUnavailable || state() != before {
							t.Fatalf("failed status audit did not preserve the complete Agent subtree: status=%d", out.Code)
						}
						if _, err := f.store.Pool.Exec(ctx, `DROP TRIGGER reject_agent_status_audit ON audit_logs`); err != nil {
							t.Fatal(err)
						}
					}
					if out := memberIdentityRequest(t, ctx, f, op); out.Code != http.StatusOK {
						t.Fatalf("Agent status update failed: status=%d", out.Code)
					}
					path := "/v1/spaces/" + f.spaceID + "/audit-logs?request_id=req_member_identity&action=member.status.update&member_id=" + f.ownerID
					page := decodeAuditPage(t, getAuditHTTP(f.handler, f.ownerToken, path))
					if len(page.Body.Data) != 1 {
						t.Fatal("Agent status update did not produce one actor-associated event")
					}
					event := page.Body.Data[0]
					if event.ActorID != f.actorID || event.MemberID != f.actorID || event.MemberType != kind || event.ResourceID != target.ID ||
						event.ResourceType != "member" || event.ResourceGroupID != target.HomeGroupID || event.SpaceID != f.spaceID ||
						event.PermissionKey != "auth.members:manage" || event.PolicyVersion != version {
						t.Fatal("Agent status audit lost the original target position or changed unrelated Space authority")
					}
					var metadata map[string]any
					if json.Unmarshal(event.Metadata, &metadata) != nil || metadata["type"] != "agent" || metadata["previous_status"] != "active" || metadata["status"] != status {
						t.Fatal("Agent status audit omitted its target type or status transition")
					}
					for _, item := range []struct{ id, key string }{{target.ID, targetKey}, {child.ID, childKey}, {peer.ID, peerKey}} {
						want := status
						if item.id == peer.ID {
							want = "active"
						}
						var current string
						if err := f.store.Pool.QueryRow(ctx, `SELECT status FROM members WHERE id = $1`, item.id).Scan(&current); err != nil || current != want {
							t.Fatal("member status update crossed the selected Agent subtree boundary")
						}
						if _, err := agents.AuthenticateKey(ctx, item.key); (err == nil) != (want == "active") {
							t.Fatal("Agent credential state disagrees with subtree status")
						}
						if strings.Contains(string(event.Metadata), item.key) {
							t.Fatal("Agent status audit exposed a credential")
						}
					}
				})
			}
		}
	}
}
