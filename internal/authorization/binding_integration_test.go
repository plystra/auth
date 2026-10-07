package authorization

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/store"
	"github.com/plystra/auth/internal/testdb"
)

var integrationDB *testdb.Harness

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	var err error
	integrationDB, err = testdb.Start(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	if err := integrationDB.Close(context.Background()); err != nil && code == 0 {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	os.Exit(code)
}

func TestBindUserRejectsNonHumanMember(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	applicationID := "mem_application_binding_test"
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO members (id, space_id, name, kind, type, binding_policy, status)
		VALUES ($1, $2, 'Application member', 'service', 'application', 'single', 'active')
	`, applicationID, spaceID); err != nil {
		t.Fatalf("insert application member: %v", err)
	}
	if err := svc.BindUser(ctx, actor.ID, spaceID, applicationID, "usr_binding_target"); err == nil {
		t.Fatal("BindUser accepted an application member")
	} else {
		assertAPIErrorCode(t, err, "VALIDATION_FAILED")
	}
}

func TestMemberTypeConstraintRejectsUnknownKind(t *testing.T) {
	ctx := context.Background()
	st, _, _, spaceID := newBindingFixture(t)
	_, err := st.Pool.Exec(ctx, `
		INSERT INTO members (id, space_id, name, kind, type, binding_policy, status)
		VALUES ('mem_invalid_type', $1, 'Invalid member', 'user', 'robot', 'single', 'active')
	`, spaceID)
	if err == nil {
		t.Fatal("members.type accepted an unknown value")
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM members WHERE id = 'mem_invalid_type'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("invalid member type row was persisted")
	}
}

func TestGroupMembershipAndParentStayWithinSpace(t *testing.T) {
	ctx := context.Background()
	st, _, actor, spaceID := newBindingFixture(t)
	otherSpaceID := "spc_other_group_integrity"
	if _, err := st.Pool.Exec(ctx, `INSERT INTO spaces (id, name, slug) VALUES ($1, 'Other Space', 'other-group-integrity')`, otherSpaceID); err != nil {
		t.Fatal(err)
	}
	firstGroupID := "grp_integrity_first"
	secondGroupID := "grp_integrity_second"
	otherGroupID := "grp_integrity_other"
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO groups (id, space_id, name) VALUES
		($1, $4, 'First'), ($2, $4, 'Second'), ($3, $5, 'Other')
	`, firstGroupID, secondGroupID, otherGroupID, spaceID, otherSpaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO group_members (group_id, member_id) VALUES ($1, $2)`, otherGroupID, actor.ID); err == nil {
		t.Fatal("database accepted a member from a different Space")
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO group_members (group_id, member_id, space_id) VALUES ($1, $2, $3)`, firstGroupID, actor.ID, otherSpaceID); err == nil {
		t.Fatal("database accepted a forged membership Space")
	}
	for _, groupID := range []string{firstGroupID, secondGroupID} {
		if _, err := st.Pool.Exec(ctx, `INSERT INTO group_members (group_id, member_id) VALUES ($1, $2)`, groupID, actor.ID); err != nil {
			t.Fatalf("member joining another group in its Space: %v", err)
		}
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM group_members WHERE member_id = $1 AND space_id = $2`, actor.ID, spaceID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("same-Space group memberships = %d, want 2", count)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE group_members SET group_id = $1 WHERE group_id = $2 AND member_id = $3`, otherGroupID, firstGroupID, actor.ID); err == nil {
		t.Fatal("database moved a membership into another Space")
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE members SET space_id = $1 WHERE id = $2`, otherSpaceID, actor.ID); err == nil {
		t.Fatal("database moved a member away from its groups")
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE groups SET space_id = $1 WHERE id = $2`, otherSpaceID, firstGroupID); err == nil {
		t.Fatal("database moved a group away from its members")
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO groups (id, space_id, name, parent_id) VALUES ('grp_integrity_cross_parent', $1, 'Invalid child', $2)`, spaceID, otherGroupID); err == nil {
		t.Fatal("database accepted a parent group from another Space")
	}
}

func TestSingleBindingSerializesConcurrentBinds(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	target, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "Shared human", "human", "single")
	if err != nil {
		t.Fatalf("create target member: %v", err)
	}
	if err := insertUser(ctx, st, "usr_binding_target", "binding-target@example.test"); err != nil {
		t.Fatal(err)
	}
	if err := insertUser(ctx, st, "usr_binding_other", "binding-other@example.test"); err != nil {
		t.Fatal(err)
	}

	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, userID := range []string{"usr_binding_target", "usr_binding_other"} {
		userID := userID
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- svc.BindUser(ctx, actor.ID, spaceID, target.ID, userID)
		}()
	}
	wg.Wait()
	close(errs)

	successes := 0
	conflicts := 0
	for err := range errs {
		if err == nil {
			successes++
			continue
		}
		var public *apierr.Error
		if !errors.As(err, &public) || public.Code != "CONFLICT" {
			t.Fatalf("unexpected concurrent bind error: %v", err)
		}
		conflicts++
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent single binding results: successes=%d conflicts=%d", successes, conflicts)
	}

	var count int
	if err := st.Pool.QueryRow(ctx, `
		SELECT count(*) FROM user_members
		WHERE member_id = $1 AND status = 'active' AND revoked_at IS NULL
	`, target.ID).Scan(&count); err != nil {
		t.Fatalf("count active bindings: %v", err)
	}
	if count != 1 {
		t.Fatalf("active binding count = %d, want 1", count)
	}
}

func TestSharedBindingRevocationPreservesOtherBindings(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	target, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "Shared member", "human", "shared")
	if err != nil {
		t.Fatal(err)
	}
	for _, user := range []struct{ id, email string }{
		{"usr_shared_one", "shared-one@example.test"},
		{"usr_shared_two", "shared-two@example.test"},
	} {
		if err := insertUser(ctx, st, user.id, user.email); err != nil {
			t.Fatal(err)
		}
		if err := svc.BindUser(ctx, actor.ID, spaceID, target.ID, user.id); err != nil {
			t.Fatal(err)
		}
	}
	if err := svc.UnbindUser(ctx, actor.ID, spaceID, target.ID, "usr_shared_one"); err != nil {
		t.Fatal(err)
	}
	var active int
	if err := st.Pool.QueryRow(ctx, `
		SELECT count(*) FROM user_members WHERE member_id = $1 AND status = 'active' AND revoked_at IS NULL
	`, target.ID).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 1 {
		t.Fatalf("active shared bindings = %d, want 1", active)
	}
	var remaining string
	if err := st.Pool.QueryRow(ctx, `
		SELECT user_id FROM user_members WHERE member_id = $1 AND status = 'active'
	`, target.ID).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != "usr_shared_two" {
		t.Fatalf("remaining binding = %q, want usr_shared_two", remaining)
	}
}

func TestSameUserCanBindMultipleMembersInOneSpace(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	if err := insertUser(ctx, st, "usr_multiple_members", "multiple-members@example.test"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"First identity", "Second identity"} {
		target, err := svc.CreateMember(ctx, actor.ID, "", spaceID, name, "human", "single")
		if err != nil {
			t.Fatal(err)
		}
		if err := svc.BindUser(ctx, actor.ID, spaceID, target.ID, "usr_multiple_members"); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM user_members WHERE user_id = $1 AND status = 'active'`, "usr_multiple_members").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("active member bindings = %d, want 2", count)
	}
}

func TestExpiredMemberBindingIsNotEligibleForCurrentMember(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	if err := insertUser(ctx, st, "usr_expiring_binding", "expiring-binding@example.test"); err != nil {
		t.Fatal(err)
	}
	target, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "Expiring identity", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.BindUser(ctx, actor.ID, spaceID, target.ID, "usr_expiring_binding"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE user_members SET expires_at = now() - interval '1 minute' WHERE user_id = 'usr_expiring_binding' AND member_id = $1`, target.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GetMemberForUser(ctx, "usr_expiring_binding", spaceID); err == nil {
		t.Fatal("expired binding was accepted as the current member")
	} else {
		assertAPIErrorCode(t, err, "PERMISSION_DENIED")
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE user_members SET expires_at = now() + interval '1 hour' WHERE user_id = 'usr_expiring_binding' AND member_id = $1`, target.ID); err != nil {
		t.Fatal(err)
	}
	if got, err := svc.GetMemberForUser(ctx, "usr_expiring_binding", spaceID); err != nil || got.ID != target.ID {
		t.Fatalf("future binding lookup = (%+v, %v), want target member", got, err)
	}
}

func TestBindingPolicyChangeRequiresPermission(t *testing.T) {
	ctx := context.Background()
	_, svc, actor, spaceID := newBindingFixture(t)
	target, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "Policy target", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	limited, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "Limited actor", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SetBindingPolicy(ctx, limited.ID, spaceID, target.ID, "shared"); err == nil {
		t.Fatal("member without auth.bindings:manage changed a binding policy")
	} else {
		assertAPIErrorCode(t, err, "NO_MATCHING_PERMISSION")
	}
	if err := svc.SetBindingPolicy(ctx, actor.ID, spaceID, target.ID, "shared"); err != nil {
		t.Fatal(err)
	}
}

func TestBindingWithPositiveAuthorityDeltaWaitsForAssignmentRights(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	target, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "Privileged identity", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	if err := insertUser(ctx, st, "usr_privileged_binding", "privileged-binding@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
		VALUES ('grt_privileged_binding', $1, '["auth.members:read"]'::jsonb, $2, 'space', $1, $3)
	`, spaceID, target.ID, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE assign_rights SET revoked_at = now() WHERE holder_member_id = $1`, actor.ID); err != nil {
		t.Fatal(err)
	}
	var versionBefore int64
	if err := st.Pool.QueryRow(ctx, `SELECT policy_version FROM spaces WHERE id = $1`, spaceID).Scan(&versionBefore); err != nil {
		t.Fatal(err)
	}
	if err := svc.BindUser(ctx, actor.ID, spaceID, target.ID, "usr_privileged_binding"); err == nil {
		t.Fatal("binding transferred authority without assignment-right coverage")
	} else {
		assertAPIErrorCode(t, err, "AUTHORITY_DELTA_NOT_COVERED")
		var public *apierr.Error
		if !errors.As(err, &public) {
			t.Fatalf("denied binding error = %v", err)
		}
		details, ok := public.Details.(map[string]string)
		if !ok || !strings.Contains(details["uncovered"], "auth.members:read@space:"+spaceID) {
			t.Fatalf("denied binding did not list the uncovered scope: %v", err)
		}
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM user_members WHERE user_id = 'usr_privileged_binding'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("denied binding persisted %d rows", count)
	}
	var versionAfter int64
	if err := st.Pool.QueryRow(ctx, `SELECT policy_version FROM spaces WHERE id = $1`, spaceID).Scan(&versionAfter); err != nil {
		t.Fatal(err)
	}
	if versionAfter != versionBefore {
		t.Fatalf("denied binding changed policy version: %d to %d", versionBefore, versionAfter)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE permissions SET status = 'disabled' WHERE key = 'auth.members:read'`); err != nil {
		t.Fatal(err)
	}
	if err := svc.BindUser(ctx, actor.ID, spaceID, target.ID, "usr_privileged_binding"); err != nil {
		t.Fatalf("dormant grant should not contribute a positive delta: %v", err)
	}
}

func TestBindingWithAssignmentRightDeltaIsRejectedWithoutDelegationCoverage(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	target, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "Assignment identity", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	if err := insertUser(ctx, st, "usr_assignment_binding", "assignment-binding@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO assign_rights (id, holder_member_id, permission_keys, anchor_space_id, covers_subtree, can_redelegate, source)
		VALUES ('ar_binding_delta', $1, '["auth.members:read"]'::jsonb, $2, true, false, 'system')
	`, target.ID, spaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE assign_rights SET revoked_at = now() WHERE holder_member_id = $1`, actor.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.BindUser(ctx, actor.ID, spaceID, target.ID, "usr_assignment_binding"); err == nil {
		t.Fatal("binding transferred an assignment right without delegation coverage")
	} else {
		assertAPIErrorCode(t, err, "AUTHORITY_DELTA_NOT_COVERED")
		var public *apierr.Error
		if !errors.As(err, &public) {
			t.Fatalf("denied assignment-right binding error = %v", err)
		}
		details, ok := public.Details.(map[string]string)
		if !ok || !strings.Contains(details["uncovered"], "permissions=auth.members:read") {
			t.Fatalf("denied assignment-right binding did not list the uncovered right: %v", err)
		}
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM user_members WHERE user_id = 'usr_assignment_binding'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("denied assignment-right binding persisted %d rows", count)
	}
}

func TestBindingWithAssignmentRightDeltaUsesDelegationCoverage(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	target, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "Covered assignment identity", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	if err := insertUser(ctx, st, "usr_assignment_covered", "assignment-covered@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO assign_rights (id, holder_member_id, permission_keys, anchor_space_id, covers_subtree, can_redelegate, source)
		VALUES ('ar_binding_covered', $1, '["auth.members:read"]'::jsonb, $2, true, false, 'system')
	`, target.ID, spaceID); err != nil {
		t.Fatal(err)
	}
	if err := svc.BindUser(ctx, actor.ID, spaceID, target.ID, "usr_assignment_covered"); err != nil {
		t.Fatalf("delegation-covered assignment binding failed: %v", err)
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM user_members WHERE user_id = 'usr_assignment_covered' AND member_id = $1 AND status = 'active'`, target.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("delegation-covered binding rows = %d, want 1", count)
	}
}

func TestBindingWithPositivePermissionDeltaUsesAssignmentCoverage(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	target, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "Covered identity", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	if err := insertUser(ctx, st, "usr_covered_binding", "covered-binding@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
		VALUES ('grt_covered_binding', $1, '["auth.members:read"]'::jsonb, $2, 'space', $1, $3)
	`, spaceID, target.ID, actor.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.BindUser(ctx, actor.ID, spaceID, target.ID, "usr_covered_binding"); err != nil {
		t.Fatalf("assignment-right-covered binding failed: %v", err)
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM user_members WHERE user_id = 'usr_covered_binding' AND member_id = $1 AND status = 'active'`, target.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("covered binding rows = %d, want 1", count)
	}
}

func newBindingFixture(t *testing.T) (*store.Store, *Service, Member, string) {
	t.Helper()
	ctx := context.Background()
	database, err := integrationDB.Clone(ctx)
	if err != nil {
		t.Fatalf("clone test database: %v", err)
	}
	t.Cleanup(func() {
		if err := database.Close(context.Background()); err != nil {
			t.Errorf("drop test database: %v", err)
		}
	})
	st, err := store.Open(ctx, database.URL)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(st.Close)
	if err := insertUser(ctx, st, "usr_binding_actor", "binding-actor@example.test"); err != nil {
		t.Fatal(err)
	}
	svc := &Service{Store: st}
	space, actor, err := svc.CreateSpace(ctx, "usr_binding_actor", "Binding Test Space", "binding-test-space")
	if err != nil {
		t.Fatalf("create binding test space: %v", err)
	}
	return st, svc, actor, space.ID
}

func insertUser(ctx context.Context, st *store.Store, id, email string) error {
	_, err := st.Pool.Exec(ctx, `
		INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ($1, $2, $2, 'test-password-hash', 'active')
	`, id, email)
	return err
}

func assertAPIErrorCode(t *testing.T, err error, want string) {
	t.Helper()
	var public *apierr.Error
	if !errors.As(err, &public) {
		t.Fatalf("error = %v, want API error %s", err, want)
	}
	if public.Code != want {
		t.Fatalf("error code = %q, want %q", public.Code, want)
	}
}
