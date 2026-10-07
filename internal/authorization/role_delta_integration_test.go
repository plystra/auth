package authorization

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
)

func TestRoleUpdateRejectsUncoveredPositiveDeltaAndRollsBack(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	target, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "Role target", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	if err := insertUser(ctx, st, "usr_role_target", "role-target@example.test"); err != nil {
		t.Fatal(err)
	}
	if err := svc.BindUser(ctx, actor.ID, spaceID, target.ID, "usr_role_target"); err != nil {
		t.Fatal(err)
	}
	role, err := svc.CreateRole(ctx, actor.ID, spaceID, "readers", "Readers", []string{"auth.members:read"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateGrant(ctx, actor.ID, spaceID, target.ID, role.ID, "space", spaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE assign_rights SET revoked_at = now() WHERE holder_member_id = $1`, actor.ID); err != nil {
		t.Fatal(err)
	}
	var beforeVersion int64
	if err := st.Pool.QueryRow(ctx, `SELECT policy_version FROM spaces WHERE id = $1`, spaceID).Scan(&beforeVersion); err != nil {
		t.Fatal(err)
	}

	_, err = svc.UpdateRole(ctx, actor.ID, spaceID, role.ID, "readers", "Expanded", []string{"auth.audit:read", "auth.members:read"})
	var public *apierr.Error
	if !errors.As(err, &public) || public.Code != "AUTHORITY_DELTA_NOT_COVERED" {
		t.Fatalf("UpdateRole error = %v, want AUTHORITY_DELTA_NOT_COVERED", err)
	}
	details, ok := public.Details.(map[string]string)
	if !ok || !strings.Contains(details["uncovered"], "auth.audit:read@space:"+spaceID) {
		t.Fatalf("uncovered details = %v", public.Details)
	}
	var permissions []string
	if err := st.Pool.QueryRow(ctx, `
		SELECT coalesce(array_agg(p.key ORDER BY p.key), '{}')
		FROM role_permissions rp JOIN permissions p ON p.id = rp.permission_id
		WHERE rp.role_id = $1
	`, role.ID).Scan(&permissions); err != nil {
		t.Fatal(err)
	}
	if len(permissions) != 1 || permissions[0] != "auth.members:read" {
		t.Fatalf("role permissions after rejected update = %v", permissions)
	}
	var afterVersion int64
	if err := st.Pool.QueryRow(ctx, `SELECT policy_version FROM spaces WHERE id = $1`, spaceID).Scan(&afterVersion); err != nil {
		t.Fatal(err)
	}
	if afterVersion != beforeVersion {
		t.Fatalf("rejected role update changed policy version: %d -> %d", beforeVersion, afterVersion)
	}
}

func TestRoleUpdateCoversPositiveDeltaForExistingRoleGrant(t *testing.T) {
	ctx := context.Background()
	_, svc, actor, spaceID := newBindingFixture(t)
	target, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "Role target", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	role, err := svc.CreateRole(ctx, actor.ID, spaceID, "readers", "Readers", []string{"auth.members:read"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateGrant(ctx, actor.ID, spaceID, target.ID, role.ID, "space", spaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdateRole(ctx, actor.ID, spaceID, role.ID, "readers", "Expanded", []string{"auth.audit:read", "auth.members:read"}); err != nil {
		t.Fatalf("covered role update failed: %v", err)
	}
	decision, _, err := svc.Check(ctx, CheckRequest{MemberID: target.ID, Permission: "auth.audit:read", ResourceSpace: spaceID})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Effect != engine.Allow {
		t.Fatalf("target audit permission = %+v, want allow", decision)
	}
}

func TestRoleGrantCreationSerializesWithRoleUpdate(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	target, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "Role lock target", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	role, err := svc.CreateRole(ctx, actor.ID, spaceID, "readers", "Readers", []string{"auth.members:read"})
	if err != nil {
		t.Fatal(err)
	}

	locked := make(chan struct{})
	release := make(chan struct{})
	lockErr := make(chan error, 1)
	go func() {
		lockErr <- st.InTx(ctx, func(q *db.Queries) error {
			if _, err := q.LockRoleInSpace(ctx, db.LockRoleInSpaceParams{ID: role.ID, SpaceID: spaceID}); err != nil {
				return err
			}
			close(locked)
			<-release
			return nil
		})
	}()
	select {
	case err := <-lockErr:
		t.Fatalf("role lock transaction ended before contender started: %v", err)
	case <-locked:
	}

	grantErr := make(chan error, 1)
	go func() {
		_, err := svc.CreateGrant(ctx, actor.ID, spaceID, target.ID, role.ID, "space", spaceID)
		grantErr <- err
	}()
	select {
	case err := <-grantErr:
		t.Fatalf("grant creation bypassed the role lock: %v", err)
	case <-time.After(300 * time.Millisecond):
	}

	close(release)
	if err := <-lockErr; err != nil {
		t.Fatal(err)
	}
	if err := <-grantErr; err != nil {
		t.Fatalf("grant failed after role lock release: %v", err)
	}
}
