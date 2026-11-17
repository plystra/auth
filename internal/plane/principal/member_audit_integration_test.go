package principal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/audit"
)

func TestMemberCreationAndBindingAuditHTTPPreservesTargetAndActorChains(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"human", "agent"} {
		for _, name := range []string{"member_create", "member_create_bound", "binding_create", "member_policy"} {
			t.Run(kind+"/"+name, func(t *testing.T) {
				t.Parallel()
				ctx := context.Background()
				f, op := newMemberIdentityOperation(t, kind, name)
				if strings.HasPrefix(name, "member_create") {
					op.body.(map[string]any)["name"] = "ply_sk_private_member_label"
				}
				reader, err := f.authz.CreateMember(ctx, f.ownerID, "usr_principal_actor", f.spaceID, "Scoped reader", "human", "single")
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
					t.Fatalf("member management failed: status=%d", out.Code)
				}
				target := f.holderID
				if strings.HasPrefix(name, "member_create") {
					var result struct{ Data struct{ ID string } }
					if err := json.Unmarshal(out.Body.Bytes(), &result); err != nil || result.Data.ID == "" {
						t.Fatal("creation did not return the new member ID")
					}
					target = result.Data.ID
				}
				actions := []string{"member.create"}
				permission := "auth.members:manage"
				switch name {
				case "member_create_bound":
					actions = append(actions, "member.binding.create")
				case "binding_create":
					actions, permission = []string{"member.binding.create"}, "auth.bindings:manage"
				case "member_policy":
					actions, permission = []string{"member.binding_policy.update"}, "auth.bindings:manage"
				}
				var snapshots []audit.Event
				for _, action := range actions {
					path := "/v1/spaces/" + f.spaceID + "/audit-logs?request_id=req_member_identity&action=" + action
					page := decodeAuditPage(t, getAuditHTTP(f.handler, f.ownerToken, path+"&member_id="+f.ownerID))
					if len(page.Body.Data) != 1 {
						t.Fatalf("%s has %d queryable events, want 1", action, len(page.Body.Data))
					}
					event := page.Body.Data[0]
					if event.ActorType != "member" || event.ActorID != f.actorID || event.MemberID != f.actorID || event.MemberType != kind ||
						event.UserID != f.userID || event.CredentialType != f.credentialType || event.Plane != "principal" || event.Outcome != "success" ||
						event.ResourceType != "member" || event.ResourceID != target || event.ResourceGroupID != op.groupID || event.SpaceID != f.spaceID ||
						event.PermissionKey != permission || event.PolicyVersion <= 0 || event.RequestID != "req_member_identity" {
						t.Fatalf("%s has incorrect actor, target, or provenance", action)
					}
					var version int64
					if err := f.store.Pool.QueryRow(ctx, `SELECT policy_version FROM spaces WHERE id = $1`, f.spaceID).Scan(&version); err != nil || event.PolicyVersion != version {
						t.Fatal("audit does not contain the committed policy version")
					}
					var ownerIDs []string
					for index, owner := range event.OwnerChain {
						ownerIDs = append(ownerIDs, owner.MemberID)
						wantType := "agent"
						if index == len(event.OwnerChain)-1 {
							wantType = "human"
						}
						if owner.SpaceID != f.spaceID || owner.MemberType != wantType {
							t.Fatal("owner snapshot has incorrect identity facts")
						}
					}
					if !slices.Equal(ownerIDs, f.owners) {
						t.Fatal("audit does not retain the complete acting owner chain")
					}
					var metadata map[string]any
					if err := json.Unmarshal(event.Metadata, &metadata); err != nil || metadata["owner_chain_complete"] != true {
						t.Fatal("audit owner provenance is incomplete")
					}
					if action == "member.create" && (metadata["type"] != "human" || metadata["binding_policy"] != "single") {
						t.Fatal("creation audit does not identify the created member kind and policy")
					}
					if action == "member.binding.create" && metadata["binding_user_id"] != "usr_member_recipient" {
						t.Fatal("binding audit confuses the bound account with the acting user")
					}
					if action == "member.binding.create" && name == "member_create_bound" && metadata["initial_binding"] != "true" {
						t.Fatal("initial binding audit does not identify the member creation path")
					}
					if action == "member.binding_policy.update" && (metadata["previous_binding_policy"] != "single" || metadata["binding_policy"] != "shared") {
						t.Fatal("binding policy audit does not retain the before and after policy")
					}
					encoded, err := json.Marshal(event)
					if err != nil {
						t.Fatal(err)
					}
					for _, forbidden := range append(slices.Clone(f.credentials), "ply_sk_", "ply_rt_", "ply_ag_", "member-recipient@example.test", "test-password-hash") {
						if strings.Contains(string(encoded), forbidden) {
							t.Fatal("member audit leaked credentials or personal labels")
						}
					}
					groupPage := decodeAuditPage(t, getAuditHTTP(f.handler, readerTokens.AccessToken, path))
					wantVisible := 0
					if op.groupID == f.fromID {
						wantVisible = 1
					}
					if len(groupPage.Body.Data) != wantVisible {
						t.Fatal("group-scoped reader crossed the member resource boundary")
					}
					snapshots = append(snapshots, event)
				}
				if kind == "agent" {
					if err := (&agent.Service{Store: f.store}).Delete(ctx, f.ownerID, f.parentID); err != nil {
						t.Fatal(err)
					}
					for _, snapshot := range snapshots {
						path := "/v1/spaces/" + f.spaceID + "/audit-logs?request_id=req_member_identity&member_id=" + f.ownerID + "&action=" + snapshot.Action
						page := decodeAuditPage(t, getAuditHTTP(f.handler, f.ownerToken, path))
						if len(page.Body.Data) != 1 || !cmp.Equal(page.Body.Data[0], snapshot) {
							t.Fatal("Agent tombstones changed the member management audit snapshot")
						}
					}
				}
			})
		}
	}
}

func TestMemberCreationHTTPDefaultsToPersonalBindingPolicy(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"human", "agent"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			f, op := newMemberIdentityOperation(t, kind, "member_create")
			delete(op.body.(map[string]any), "binding_policy")
			out := memberIdentityRequest(t, context.Background(), f, op)
			var result struct {
				Data struct {
					ID            string `json:"id"`
					BindingPolicy string `json:"binding_policy"`
				}
			}
			if out.Code != http.StatusOK || json.Unmarshal(out.Body.Bytes(), &result) != nil || result.Data.ID == "" || result.Data.BindingPolicy != "single" {
				t.Fatalf("omitted policy did not create a personal member: status=%d", out.Code)
			}
		})
	}
}

func TestMemberCreationAndBindingAuditHTTPFailureRollsBackStateAndProofs(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"human", "agent"} {
		for _, scenario := range []struct{ name, operation, reject string }{
			{"create", "member_create", "member.create"},
			{"create_bound", "member_create_bound", "member.create"},
			{"initial_binding", "member_create_bound", "member.binding.create"},
			{"bind", "binding_create", "member.binding.create"},
			{"policy", "member_policy", "member.binding_policy.update"},
			{"shared_initial_binding", "member_create_bound", "member.binding.create"},
		} {
			t.Run(kind+"/"+scenario.name, func(t *testing.T) {
				t.Parallel()
				ctx := context.Background()
				f, op := newMemberIdentityOperation(t, kind, scenario.operation)
				if scenario.name == "shared_initial_binding" {
					op.body.(map[string]any)["binding_policy"] = "shared"
					if kind == "agent" {
						op = approveSharedMemberCreation(t, f, op)
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
				if _, err := f.store.Pool.Exec(ctx, `CREATE FUNCTION reject_member_change_audit() RETURNS trigger LANGUAGE plpgsql AS $$
					BEGIN IF NEW.request_id = 'req_member_identity' AND NEW.action = TG_ARGV[0] THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END; $$`); err != nil {
					t.Fatal(err)
				}
				if _, err := f.store.Pool.Exec(ctx, fmt.Sprintf(`CREATE TRIGGER reject_member_change_audit BEFORE INSERT ON audit_logs
					FOR EACH ROW EXECUTE FUNCTION reject_member_change_audit('%s')`, scenario.reject)); err != nil {
					t.Fatal(err)
				}
				before := state()
				out := memberIdentityRequest(t, ctx, f, op)
				if out.Code != http.StatusServiceUnavailable || !strings.Contains(out.Body.String(), `"code":"UNAVAILABLE"`) {
					t.Fatalf("audit failure returned status %d, want UNAVAILABLE", out.Code)
				}
				if state() != before {
					t.Fatal("audit failure changed members, bindings, policy versions, audits, approval, or step-up")
				}
				if _, err := f.store.Pool.Exec(ctx, `DROP TRIGGER reject_member_change_audit ON audit_logs`); err != nil {
					t.Fatal(err)
				}
				out = memberIdentityRequest(t, ctx, f, op)
				if out.Code != http.StatusOK {
					t.Fatalf("original request could not retry after audit recovery: status=%d", out.Code)
				}
				var successes int
				if err := f.store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE request_id = 'req_member_identity'
					AND action IN ('member.create', 'member.binding.create', 'member.binding_policy.update')`).Scan(&successes); err != nil {
					t.Fatal(err)
				}
				want := 1
				if scenario.operation == "member_create_bound" {
					want = 2
				}
				if successes != want {
					t.Fatalf("recovered request committed %d member audit events, want %d", successes, want)
				}
			})
		}
	}
}

func TestMemberBindingAuditHTTPUsesSpaceForAmbiguousPositions(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"binding_create", "member_policy"} {
		for _, position := range []string{"no_groups", "multiple_groups"} {
			t.Run(name+"/"+position, func(t *testing.T) {
				t.Parallel()
				ctx := context.Background()
				f, op := newMemberIdentityOperation(t, "human", name)
				var err error
				if position == "no_groups" {
					err = f.authz.RemoveMemberFromGroup(ctx, f.ownerID, f.spaceID, f.fromID, f.holderID)
				} else {
					err = f.authz.AddMemberToGroup(ctx, f.ownerID, f.spaceID, f.toID, f.holderID)
				}
				if err != nil {
					t.Fatal(err)
				}
				if out := memberIdentityRequest(t, ctx, f, op); out.Code != http.StatusOK {
					t.Fatalf("member mutation failed: status=%d", out.Code)
				}
				action := "member.binding.create"
				if name == "member_policy" {
					action = "member.binding_policy.update"
				}
				path := "/v1/spaces/" + f.spaceID + "/audit-logs?request_id=req_member_identity&action=" + action
				page := decodeAuditPage(t, getAuditHTTP(f.handler, f.ownerToken, path))
				if len(page.Body.Data) != 1 || page.Body.Data[0].ResourceGroupID != "" || page.Body.Data[0].ResourceID != f.holderID {
					t.Fatal("ambiguous member position did not use the Space audit boundary")
				}
				if _, err := f.store.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, f.ownerID); err != nil {
					t.Fatal(err)
				}
				seedAuditGroupReader(t, f.store, f.spaceID, f.ownerID, f.ownerID, f.fromID)
				limited := decodeAuditPage(t, getAuditHTTP(f.handler, f.ownerToken, path))
				if len(limited.Body.Data) != 0 {
					t.Fatal("a group-only auditor read a Space-wide member change")
				}
			})
		}
	}
}
