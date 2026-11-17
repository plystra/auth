package principal

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/google/go-cmp/cmp"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/store"
)

type governanceAuditFixture struct {
	store                                        *store.Store
	authz                                        *authorization.Service
	sessions                                     *session.Service
	handler                                      http.Handler
	ownerID, actorID, spaceID, token, sessionID  string
	ownerToken, userID, credentialType, parentID string
	rootID, fromID, toID, movingID, holderID     string
	roleID, anchorGroupID                        string
	right                                        authorization.AssignmentRight
	owners, credentials                          []string
}

func newGovernanceAuditFixture(t *testing.T, kind, anchor string) governanceAuditFixture {
	t.Helper()
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, _ := newPrincipalFixture(t)
	authz.StepUp = sessions
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", owner.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	f := governanceAuditFixture{
		store: st, authz: authz, sessions: sessions, ownerID: owner.ID, actorID: owner.ID, spaceID: spaceID,
		token: tokens.AccessToken, ownerToken: tokens.AccessToken, sessionID: tokens.SessionID,
		userID: "usr_principal_actor", credentialType: "user_access_token",
		credentials: []string{tokens.AccessToken, tokens.RefreshToken},
	}
	group := func(name, parentID string) string {
		t.Helper()
		created, err := authz.CreateGroup(ctx, owner.ID, spaceID, name, parentID)
		if err != nil {
			t.Fatal(err)
		}
		return created.ID
	}
	f.rootID = group("Governance audit root", "")
	f.fromID = group("Source team", f.rootID)
	f.toID = group("Destination team", f.rootID)
	f.movingID = group("Moving team", f.fromID)
	if anchor == "group" {
		f.anchorGroupID = f.fromID
	}
	holder, err := authz.CreateMember(ctx, owner.ID, "", spaceID, "Delegation recipient", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	f.holderID = holder.ID
	role, err := authz.CreateRole(ctx, owner.ID, spaceID, "Original role", "", []string{"auth.members:read"})
	if err != nil {
		t.Fatal(err)
	}
	f.roleID = role.ID
	f.right, err = authz.CreateAssignmentRight(ctx, owner.ID, spaceID, holder.ID, []string{"auth.members:read"}, "", f.anchorGroupID, false, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	agents := &agent.Service{Store: st, StepUp: sessions}
	if kind == "agent" {
		permissions := []string{"auth.groups:manage", "auth.roles:manage", "auth.assign_rights:manage", "auth.members:read", "auth.audit:read"}
		current := owner.ID
		expiresAt := time.Now().Add(time.Hour).Truncate(time.Second)
		for _, name := range []string{"Governance parent", "Governance caller"} {
			created, key, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: current, CreatedByUser: "usr_principal_actor", Name: name, ExpiresAt: expiresAt})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := authz.ReplaceAgentGrants(ctx, current, spaceID, created.ID, permissions, "space", spaceID); err != nil {
				t.Fatal(err)
			}
			if _, err := authz.CreateAssignmentRight(ctx, current, spaceID, created.ID, []string{"auth.members:read"}, spaceID, "", true, true, nil); err != nil {
				t.Fatal(err)
			}
			f.credentials = append(f.credentials, key)
			if current != owner.ID {
				f.parentID = current
			}
			current = created.ID
		}
		issued, err := sessions.CreateAgentAccess(ctx, current, spaceID, security.DefaultApplicationAudience)
		if err != nil {
			t.Fatal(err)
		}
		f.actorID, f.token, f.userID, f.credentialType = current, issued.AccessToken, "", "agent_access_token"
		f.owners = []string{f.parentID, owner.ID}
		f.credentials = append(f.credentials, issued.AccessToken)
	}
	mux := http.NewServeMux()
	(&API{Authorization: authz, Sessions: sessions, Agents: agents}).Register(humago.New(mux, route.HumaConfig("governance audit test", "1.0.0")))
	f.handler = route.Middleware(route.Principal, mux)
	return f
}

type governanceAuditOperation struct {
	method, path, action, permission, resourceType, resourceID, groupID string
	body                                                                any
}

func (f governanceAuditFixture) operation(t *testing.T, name string) governanceAuditOperation {
	t.Helper()
	base := "/v1/spaces/" + f.spaceID
	op := governanceAuditOperation{method: http.MethodPost}
	switch name {
	case "group_create":
		op.path, op.action, op.permission, op.resourceType = base+"/groups", "group.create", "auth.groups:manage", "group"
		op.body = map[string]any{"name": "ply_sk_private_group_label", "parent_group_id": f.fromID}
	case "group_move":
		op.path, op.action, op.permission, op.resourceType = base+"/groups/"+f.movingID+"/move", "group.move", "auth.groups:manage", "group"
		op.resourceID, op.groupID = f.movingID, f.movingID
		op.body = map[string]any{"parent_group_id": f.toID}
	case "role_create":
		op.path, op.action, op.permission, op.resourceType = base+"/roles", "role.create", "auth.roles:manage", "role"
		op.body = map[string]any{"name": "ply_sk_private_role_label", "description": "ply_rt_private_description", "permissions": []string{"auth.members:read"}}
	case "role_update":
		op.method, op.path, op.action, op.permission, op.resourceType = http.MethodPatch, base+"/roles/"+f.roleID, "role.update", "auth.roles:manage", "role"
		op.resourceID = f.roleID
		op.body = map[string]any{"name": "Updated role", "description": "ply_rt_private_description", "permissions": []string{"auth.members:manage"}}
	case "right_create":
		op.path, op.action, op.permission, op.resourceType = base+"/assign-rights", "assign_right.create", "auth.assign_rights:manage", "assign_right"
		op.groupID = f.anchorGroupID
		op.body = map[string]any{"holder_member_id": f.holderID, "permissions": []string{"auth.members:read"}, "covers_subtree": false, "can_redelegate": false}
		anchorSpace := ""
		if f.anchorGroupID != "" {
			op.body.(map[string]any)["anchor_group_id"] = f.anchorGroupID
		} else {
			anchorSpace = f.spaceID
			op.body.(map[string]any)["anchor_space_id"] = anchorSpace
		}
		if f.userID != "" {
			seedStepUpProof(t, f.store, f.sessionID, "assignment_rights.create", map[string]any{
				"space_id": f.spaceID, "holder_member_id": f.holderID, "permissions": []string{"auth.members:read"},
				"anchor_space_id": anchorSpace, "anchor_group_id": f.anchorGroupID,
				"covers_subtree": false, "can_redelegate": false, "expires_at": (*time.Time)(nil),
			})
		}
	case "right_revoke":
		op.method, op.path, op.action, op.permission, op.resourceType = http.MethodDelete, base+"/assign-rights/"+f.right.ID, "assign_right.revoke", "auth.assign_rights:manage", "assign_right"
		op.resourceID, op.groupID = f.right.ID, f.anchorGroupID
		if f.userID != "" {
			seedStepUpProof(t, f.store, f.sessionID, "assignment_rights.revoke", map[string]any{"space_id": f.spaceID, "assignment_right_id": f.right.ID})
		}
	default:
		t.Fatalf("unknown governance operation %s", name)
	}
	return op
}

func TestGovernanceAuditHTTPPreservesResourceAndActorChains(t *testing.T) {
	for _, kind := range []string{"human", "agent"} {
		for _, anchor := range []string{"space", "group"} {
			t.Run(kind+"/"+anchor, func(t *testing.T) {
				ctx := context.Background()
				f := newGovernanceAuditFixture(t, kind, anchor)
				auditPath := "/v1/spaces/" + f.spaceID + "/audit-logs"
				reader, err := f.authz.CreateMember(ctx, f.ownerID, "usr_principal_actor", f.spaceID, "Team auditor", "human", "single")
				if err != nil {
					t.Fatal(err)
				}
				seedAuditGroupReader(t, f.store, f.spaceID, f.ownerID, reader.ID, f.fromID)
				readerToken, err := f.sessions.CreateForMember(ctx, "usr_principal_actor", reader.ID, nil, "test", 1)
				if err != nil {
					t.Fatal(err)
				}
				var snapshots []audit.Event
				for _, name := range []string{"group_create", "group_move", "role_create", "role_update", "right_create", "right_revoke"} {
					op := f.operation(t, name)
					requestID := "req_governance_" + name
					out := applicationAuditRequest(t, f.handler, op.method, op.path, f.token, requestID, op.body)
					if out.Code != http.StatusOK {
						t.Fatalf("%s failed: status=%d", name, out.Code)
					}
					var result struct {
						Data struct {
							ID       string `json:"id"`
							ParentID string `json:"parent_id"`
						} `json:"data"`
					}
					if err := json.Unmarshal(out.Body.Bytes(), &result); err != nil {
						t.Fatal(err)
					}
					if op.resourceID == "" {
						op.resourceID = result.Data.ID
					}
					if name == "group_create" {
						op.groupID = result.Data.ID
					}
					page := decodeAuditPage(t, getAuditHTTP(f.handler, f.ownerToken, auditPath+"?request_id="+requestID+"&member_id="+f.ownerID))
					if len(page.Body.Data) != 1 {
						t.Fatalf("%s has %d queryable events, want 1", name, len(page.Body.Data))
					}
					event := page.Body.Data[0]
					if event.Action != op.action || event.ActorType != "member" || event.ActorID != f.actorID || event.MemberID != f.actorID || event.MemberType != kind || event.UserID != f.userID ||
						event.CredentialType != f.credentialType || event.Plane != "principal" || event.ResourceType != op.resourceType || event.ResourceID != op.resourceID ||
						event.SpaceID != f.spaceID || event.ResourceGroupID != op.groupID || event.PermissionKey != op.permission || event.PolicyVersion <= 0 || event.Outcome != "success" {
						t.Fatalf("%s has incorrect audit identity or resource", name)
					}
					var version int64
					if err := f.store.Pool.QueryRow(ctx, `SELECT policy_version FROM spaces WHERE id = $1`, f.spaceID).Scan(&version); err != nil || event.PolicyVersion != version {
						t.Fatalf("%s audit did not preserve the committed policy version: %v", name, err)
					}
					var owners []string
					for _, owner := range event.OwnerChain {
						owners = append(owners, owner.MemberID)
						if owner.SpaceID != f.spaceID {
							t.Fatal("governance owner snapshot changed the owner's Space")
						}
					}
					if !slices.Equal(owners, f.owners) {
						t.Fatal("governance event lost its actor's owner chain")
					}
					var metadata map[string]any
					if err := json.Unmarshal(event.Metadata, &metadata); err != nil {
						t.Fatal(err)
					}
					if metadata["owner_chain_complete"] != true {
						t.Fatal("governance owner chain is not complete")
					}
					switch name {
					case "group_create":
						if metadata["parent_group_id"] != f.fromID {
							t.Fatal("group creation lost its parent reference")
						}
					case "group_move":
						if metadata["previous_parent_group_id"] != f.fromID || metadata["parent_group_id"] != f.toID {
							t.Fatal("group movement lost its before/after parent references")
						}
					case "right_create", "right_revoke":
						parentID := result.Data.ParentID
						if name == "right_revoke" {
							parentID = f.right.ParentID
						}
						if metadata["holder_member_id"] != f.holderID || parentID == "" || metadata["parent_assignment_right_id"] != parentID {
							t.Fatal("assignment right lost its recipient or delegation parent")
						}
					}
					serialized, err := json.Marshal(event)
					if err != nil {
						t.Fatal(err)
					}
					for _, forbidden := range append(f.credentials, "ply_sk_", "ply_rt_", "ply_ag_") {
						if strings.Contains(string(serialized), forbidden) {
							t.Fatal("governance audit leaked credential content or private labels")
						}
					}
					groupPage := decodeAuditPage(t, getAuditHTTP(f.handler, readerToken.AccessToken, auditPath+"?request_id="+requestID))
					visible := name == "group_create" || anchor == "group" && strings.HasPrefix(name, "right_")
					if visible && len(groupPage.Body.Data) != 1 || !visible && len(groupPage.Body.Data) != 0 {
						t.Fatalf("team reader crossed the resource boundary for %s", name)
					}
					snapshots = append(snapshots, event)
				}
				if kind == "agent" {
					if err := (&agent.Service{Store: f.store}).Delete(ctx, f.ownerID, f.parentID); err != nil {
						t.Fatal(err)
					}
					for _, snapshot := range snapshots {
						page := decodeAuditPage(t, getAuditHTTP(f.handler, f.ownerToken, auditPath+"?request_id="+snapshot.RequestID+"&member_id="+f.ownerID))
						if len(page.Body.Data) != 1 || !cmp.Equal(page.Body.Data[0], snapshot) {
							t.Fatal("Agent tombstones changed a governance audit snapshot")
						}
					}
				}
			})
		}
	}
}

func TestGovernanceAuditHTTPFailureRollsBackStateAndStepUp(t *testing.T) {
	for _, kind := range []string{"human", "agent"} {
		for _, name := range []string{"group_create", "group_move", "role_create", "role_update", "right_create", "right_revoke"} {
			t.Run(kind+"/"+name, func(t *testing.T) {
				ctx := context.Background()
				f := newGovernanceAuditFixture(t, kind, "group")
				op := f.operation(t, name)
				if _, err := f.store.Pool.Exec(ctx, `CREATE FUNCTION reject_governance_audit() RETURNS trigger LANGUAGE plpgsql AS $$
					BEGIN IF NEW.request_id = 'req_governance_failure' THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END; $$;
					CREATE TRIGGER reject_governance_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_governance_audit()`); err != nil {
					t.Fatal(err)
				}
				state := func() string {
					t.Helper()
					var serialized string
					if err := f.store.Pool.QueryRow(ctx, `SELECT jsonb_build_object(
						'groups', (SELECT jsonb_agg(to_jsonb(g) ORDER BY id) FROM groups g),
						'roles', (SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM roles r),
						'permissions', (SELECT jsonb_agg(to_jsonb(p) ORDER BY role_id, permission_id) FROM role_permissions p),
						'rights', (SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM assign_rights r),
						'spaces', (SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM spaces s),
						'audits', (SELECT count(*) FROM audit_logs),
						'step_up', (SELECT jsonb_build_object('operation', step_up_operation, 'digest', encode(step_up_digest, 'hex'), 'expires_at', step_up_expires_at) FROM sessions WHERE id = $1)
						)::text`, f.sessionID).Scan(&serialized); err != nil {
						t.Fatal(err)
					}
					return serialized
				}
				before := state()
				out := applicationAuditRequest(t, f.handler, op.method, op.path, f.token, "req_governance_failure", op.body)
				if out.Code != http.StatusServiceUnavailable || !strings.Contains(out.Body.String(), "UNAVAILABLE") {
					t.Fatalf("governance audit failure returned status=%d", out.Code)
				}
				if state() != before {
					t.Fatal("audit failure changed groups, roles, permissions, assignment rights, policy versions, or step-up")
				}
				if _, err := f.store.Pool.Exec(ctx, `DROP TRIGGER reject_governance_audit ON audit_logs`); err != nil {
					t.Fatal(err)
				}
				out = applicationAuditRequest(t, f.handler, op.method, op.path, f.token, "req_governance_failure", op.body)
				if out.Code != http.StatusOK {
					t.Fatalf("retry after audit recovery returned status=%d", out.Code)
				}
				page := decodeAuditPage(t, getAuditHTTP(f.handler, f.ownerToken, "/v1/spaces/"+f.spaceID+"/audit-logs?request_id=req_governance_failure"))
				if len(page.Body.Data) != 1 || page.Body.Data[0].Action != op.action || page.Body.Data[0].ActorID != f.actorID {
					t.Fatal("recovered governance operation did not produce exactly one event")
				}
			})
		}
	}
}
