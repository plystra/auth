package protocol

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/enterprise"
)

func TestSSOConnectionChecksMappedGrantAuthority(t *testing.T) {
	const revokeRights = "UPDATE assign_rights SET revoked_at=now() WHERE holder_member_id=@owner"
	cases := []struct {
		name, setup, wantCode string
	}{
		{name: "covered"},
		{name: "missing assignment right", setup: revokeRights, wantCode: "AUTHORITY_DELTA_NOT_COVERED"},
		{name: "group right cannot cover a Space grant", setup: revokeRights + `;
			INSERT INTO groups (id,space_id,name,kind,status) VALUES ('grp_mapping',@space,'Group','standard','active');
			INSERT INTO assign_rights (id,holder_member_id,permission_keys,anchor_group_id,covers_subtree,can_redelegate,source)
			VALUES ('ar_mapping',@owner,'["auth.members:read"]','grp_mapping',true,false,'system')`, wantCode: "AUTHORITY_DELTA_NOT_COVERED"},
		{name: "use-only envelope", setup: `INSERT INTO space_envelopes (space_id) VALUES (@space);
			INSERT INTO space_envelope_entries (space_id, permission_id, mode)
			SELECT @space,id,CASE WHEN key='auth.members:read' THEN 'use' ELSE 'delegate' END FROM permissions WHERE delegable`, wantCode: "AUTHORITY_DELTA_NOT_COVERED"},
		{name: "assignment management required", setup: `UPDATE permissions SET status='disabled' WHERE key='auth.grants:assign'`, wantCode: "PERMISSION_DISABLED"},
		{name: "deprecated grant", setup: `UPDATE permissions SET status='deprecated' WHERE key='auth.members:read'`, wantCode: "AUTHORITY_DELTA_NOT_COVERED"},
		{name: "installation role", setup: `INSERT INTO applications (id,space_id,name,client_id) VALUES ('app_mapping',@space,'App','mapping');
			INSERT INTO members (id,space_id,name,type) VALUES ('mem_mapping_app',@space,'App','application');
			INSERT INTO application_installations (id,application_id,space_id,member_id,role_id,scope,approved_permissions,installed_by)
			VALUES ('ins_mapping','app_mapping',@space,'mem_mapping_app','rol_mapping','space','[]',@owner)`, wantCode: "VALIDATION_FAILED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			st, _, svc, owner, spaceID, provider := newSSOHTTPFixture(t)
			if _, err := st.Pool.Exec(ctx, `INSERT INTO roles (id,space_id,name,managed) VALUES ('rol_mapping',$1,'Reader',false);
				INSERT INTO role_permissions (role_id,permission_id) SELECT 'rol_mapping',id FROM permissions WHERE key='auth.members:read'`, pgx.QueryExecModeSimpleProtocol, spaceID); err != nil {
				t.Fatal(err)
			}
			if tc.setup != "" {
				if _, err := st.Pool.Exec(ctx, tc.setup, pgx.QueryExecModeSimpleProtocol, pgx.NamedArgs{"space": spaceID, "owner": owner.ID}); err != nil {
					t.Fatal(err)
				}
			}
			in := ssoMappingInput(provider.issuer, "rol_mapping")
			got, err := svc.CreateConnection(authorization.WithHumanActor(ctx, owner.ID, "usr_sso_http_owner"), owner.ID, spaceID, in)
			if tc.wantCode == "" {
				if err != nil || got.RoleMappings["engineering"] != "rol_mapping" {
					t.Fatalf("covered mapping failed: %v", err)
				}
				return
			}
			var apiErr *apierr.Error
			if !errors.As(err, &apiErr) || apiErr.Code != tc.wantCode {
				t.Fatalf("got %v, want %s", err, tc.wantCode)
			}
			var writes int
			if err := st.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM sso_connections WHERE space_id=$1) +
				(SELECT count(*) FROM audit_logs WHERE action='sso.connection.create' AND outcome='success')`, spaceID).Scan(&writes); err != nil || writes != 0 {
				t.Fatalf("denied mapping persisted connection or success audit: %d, %v", writes, err)
			}
		})
	}
}

func ssoMappingInput(issuer, roleID string) enterprise.ConnectionInput {
	return enterprise.ConnectionInput{Name: "Workforce", Provider: "oidc", Issuer: issuer, ClientID: "mapping-client",
		ClientSecret: "test-secret", RedirectURI: "https://auth.test/v1/sso/{connection_id}/callback",
		RoleMappings: map[string]string{"engineering": roleID, "platform": roleID}}
}

func TestSSOMappingEmptyDeltaAndManagementBeforeRoleDisclosure(t *testing.T) {
	ctx := context.Background()
	st, _, svc, owner, spaceID, provider := newSSOHTTPFixture(t)
	if _, err := st.Pool.Exec(ctx, `INSERT INTO roles (id,space_id,name,managed) VALUES ('rol_empty_mapping',$1,'Empty',false);
		UPDATE permissions SET status='disabled' WHERE key='auth.grants:assign';
		UPDATE assign_rights SET revoked_at=now() WHERE holder_member_id=$2`, pgx.QueryExecModeSimpleProtocol, spaceID, owner.ID); err != nil {
		t.Fatal(err)
	}
	ctx = authorization.WithHumanActor(ctx, owner.ID, "usr_sso_http_owner")
	if _, err := svc.CreateConnection(ctx, owner.ID, spaceID, ssoMappingInput(provider.issuer, "rol_empty_mapping")); err != nil {
		t.Fatalf("management alone must cover an empty role: %v", err)
	}
	if _, err := st.Pool.Exec(ctx, "UPDATE permissions SET status='disabled' WHERE key='auth.connections:manage'"); err != nil {
		t.Fatal(err)
	}
	for _, roleID := range []string{"rol_empty_mapping", "rol_missing"} {
		_, err := svc.CreateConnection(ctx, owner.ID, spaceID, ssoMappingInput(provider.issuer, roleID))
		var apiErr *apierr.Error
		if !errors.As(err, &apiErr) || apiErr.Code != "PERMISSION_DISABLED" {
			t.Fatalf("management denial for %s = %v", roleID, err)
		}
	}
}

func TestSSOMappingRechecksRoleAfterConcurrentEdit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st, _, svc, owner, spaceID, provider := newSSOHTTPFixture(t)
	const roleID = "rol_concurrent_mapping"
	if _, err := st.Pool.Exec(ctx, `INSERT INTO roles (id,space_id,name,managed) VALUES ($1,$2,'Concurrent mapping',false);
		UPDATE assign_rights SET revoked_at=now() WHERE holder_member_id=$3`, pgx.QueryExecModeSimpleProtocol, roleID, spaceID, owner.ID); err != nil {
		t.Fatal(err)
	}
	edit, err := st.BeginIdempotency(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = edit.Rollback(context.Background()) }()
	if err := st.InTx(edit.Context(ctx), func(q *db.Queries) error {
		if _, err := q.LockRoleInSpace(ctx, db.LockRoleInSpaceParams{SpaceID: spaceID, ID: roleID}); err != nil {
			return err
		}
		p, err := q.GetPermissionByKey(ctx, db.GetPermissionByKeyParams{Key: "auth.members:read"})
		if err != nil {
			return err
		}
		return q.GrantRolePermission(ctx, db.GrantRolePermissionParams{RoleID: roleID, PermissionID: p.ID})
	}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := svc.CreateConnection(authorization.WithHumanActor(ctx, owner.ID, "usr_sso_http_owner"), owner.ID, spaceID, ssoMappingInput(provider.issuer, roleID))
		done <- err
	}()
	for {
		select {
		case err := <-done:
			t.Fatalf("configuration completed before the role edit: %v", err)
		default:
		}
		var waiting bool
		if err := st.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname=current_database()
			AND wait_event_type='Lock' AND query LIKE '%LockRoleInSpace%')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := edit.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var apiErr *apierr.Error
	if err := <-done; !errors.As(err, &apiErr) || apiErr.Code != "AUTHORITY_DELTA_NOT_COVERED" {
		t.Fatalf("configuration after role expansion = %v", err)
	}
}

func TestSSOMappingRequiresCurrentAgentOwnerAssignmentAuthority(t *testing.T) {
	ctx := context.Background()
	st, authorizer, svc, owner, spaceID, provider := newSSOHTTPFixture(t)
	actor, _, err := (&agent.Service{Store: st}).Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, CreatedByUser: "usr_sso_http_owner", Name: "SSO manager"})
	if err != nil {
		t.Fatal(err)
	}
	role, err := authorizer.CreateRole(ctx, owner.ID, spaceID, "Mapped reader", "", []string{"auth.members:read"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE permissions SET agent_approval='none' WHERE key='auth.connections:manage';
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
		VALUES ('grt_sso_manager',$1,'["auth.connections:manage","auth.grants:assign"]',$2,'space',$1,$3)`, pgx.QueryExecModeSimpleProtocol, spaceID, actor.ID, owner.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := authorizer.CreateAssignmentRight(ctx, owner.ID, spaceID, actor.ID, []string{"auth.members:read"}, spaceID, "", false, false, nil); err != nil {
		t.Fatal(err)
	}
	in := ssoMappingInput(provider.issuer, role.ID)
	if _, err := svc.CreateConnection(ctx, actor.ID, spaceID, in); err != nil {
		t.Fatalf("owner-covered Agent mapping failed: %v", err)
	}
	if _, err := st.Pool.Exec(ctx, "UPDATE assign_rights SET revoked_at=now() WHERE holder_member_id=$1", owner.ID); err != nil {
		t.Fatal(err)
	}
	in.Name = "Second connection"
	_, err = svc.CreateConnection(ctx, actor.ID, spaceID, in)
	var apiErr *apierr.Error
	if !errors.As(err, &apiErr) || apiErr.Code != "AUTHORITY_DELTA_NOT_COVERED" {
		t.Fatalf("Agent mapping after owner lost assignment authority: %v", err)
	}
}
