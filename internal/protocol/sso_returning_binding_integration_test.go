package protocol

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/db"
)

func TestSSOReturningIdentityCannotReplaceInactiveSpaceBinding(t *testing.T) {
	for _, tc := range []struct{ name, change string }{
		{"revoked binding", "UPDATE user_members SET revoked_at=now(),status='revoked' WHERE member_id=$1"},
		{"expired binding", "UPDATE user_members SET expires_at=now()-interval '1 minute' WHERE member_id=$1"},
		{"suspended member", "UPDATE members SET status='suspended' WHERE id=$1"},
		{"removed member", "UPDATE members SET status='removed' WHERE id=$1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			f := newJITMappingFixture(t, false)
			first := f.login(t, "returning", "engineering")
			if _, err := f.st.Pool.Exec(ctx, tc.change, first); err != nil {
				t.Fatal(err)
			}
			in := f.start(t, "returning", "engineering")
			before := f.counts(t)
			_, err := f.svc.Callback(ctx, in)
			f.assertDenied(t, err, "invalid_grant", before)
			var e *apierr.Error
			if !errors.As(err, &e) || e.Message != "the SSO identity is not valid for this connection" || e.Details != nil {
				t.Fatal("SSO denial disclosed the member or binding state")
			}
		})
	}
}

func TestSSOReturningBindingExpiryDuringLockWaitDeniesLogin(t *testing.T) {
	f := newJITMappingFixture(t, false)
	memberID := f.login(t, "lock-wait", "engineering")
	in := f.start(t, "lock-wait", "engineering")
	before := f.counts(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	var userID string
	if err := f.st.Pool.QueryRow(ctx, "SELECT user_id FROM user_members WHERE member_id=$1", memberID).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	gate, err := f.st.BeginIdempotency(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gate.Rollback(context.Background()) }()
	if err := f.st.InTx(gate.Context(ctx), func(q *db.Queries) error {
		_, err := q.LockUserForAuthorization(ctx, db.LockUserForAuthorizationParams{ID: userID})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := f.svc.Callback(ctx, in); done <- err }()
	var started time.Time
	for {
		var txStart *time.Time
		if err := f.st.Pool.QueryRow(ctx, `SELECT min(xact_start) FROM pg_stat_activity WHERE datname=current_database()
			AND wait_event_type='Lock' AND query LIKE '%LockUserForAuthorization%'`).Scan(&txStart); err != nil {
			t.Fatal(err)
		}
		if txStart != nil {
			started = *txStart
			break
		}
		select {
		case err := <-done:
			t.Fatalf("SSO did not wait for its account lock: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	var expired bool
	if err := f.st.Pool.QueryRow(ctx, `UPDATE user_members SET expires_at=$2 WHERE member_id=$1
		RETURNING expires_at < clock_timestamp()`, memberID, started.Add(time.Microsecond)).Scan(&expired); err != nil || !expired {
		t.Fatalf("did not exercise binding expiry after the callback transaction began: %v", err)
	}
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	f.assertDenied(t, <-done, "invalid_grant", before)
}

func TestSSOReturningIdentityUsesOtherActiveSpaceMembership(t *testing.T) {
	ctx := t.Context()
	f := newJITMappingFixture(t, false)
	first := f.login(t, "shared-identity", "engineering")
	if _, err := f.st.Pool.Exec(ctx, `INSERT INTO members (id,space_id,name,type,binding_policy)
		VALUES ('mem_other_binding',$1,'Another valid binding','human','single');
		INSERT INTO user_members(user_id,member_id) SELECT user_id,'mem_other_binding' FROM user_members WHERE member_id=$2;
		UPDATE user_members SET revoked_at=now(),status='revoked' WHERE member_id=$2`, pgx.QueryExecModeSimpleProtocol, f.space, first); err != nil {
		t.Fatal(err)
	}
	if other := f.login(t, "shared-identity", "engineering"); other != "mem_other_binding" || f.grantCount(t, other) != 0 {
		t.Fatal("returning SSO membership was recreated or received a replayed mapped grant")
	}
}

func TestSSOOnlyConsidersBindingHistoryInConnectionSpace(t *testing.T) {
	ctx := context.Background()
	f := newJITMappingFixture(t, false)
	first := f.login(t, "same-external-user", "engineering")
	if _, err := f.st.Pool.Exec(ctx, "UPDATE user_members SET revoked_at=now(),status='revoked' WHERE member_id=$1", first); err != nil {
		t.Fatal(err)
	}
	another, manager, err := f.svc.Authorization.CreateSpace(ctx, "usr_sso_http_owner", "Separate Space", "separate-space")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.Pool.Exec(ctx, `INSERT INTO authorization_grants (id,space_id,permission_keys,grantee_member_id,scope,anchor_space_id,granted_by)
		VALUES ('grt_other_space_sso',$1,'["auth.connections:manage"]',$2,'space',$1,$2)`, another.ID, manager.ID); err != nil {
		t.Fatal(err)
	}
	input := ssoMappingInput(f.provider.issuer, "")
	input.RoleMappings = nil
	f.connection, err = f.svc.CreateConnection(authorization.WithHumanActor(ctx, manager.ID, "usr_sso_http_owner"), manager.ID, another.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	next := f.login(t, "same-external-user", "engineering")
	var sameUser bool
	if err := f.st.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM user_members old
		JOIN user_members current ON current.user_id=old.user_id JOIN members m ON m.id=current.member_id
		WHERE old.member_id=$1 AND current.member_id=$2 AND current.revoked_at IS NULL AND m.space_id=$3)`, first, next, another.ID).Scan(&sameUser); err != nil || !sameUser {
		t.Fatalf("legitimate first login in a separate Space did not bind the existing identity: %v", err)
	}
}
