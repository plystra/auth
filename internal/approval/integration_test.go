package approval

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/stepup"
	"github.com/plystra/auth/internal/store"
	"github.com/plystra/auth/internal/testdb"
)

var approvalDB *testdb.Harness

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var err error
	approvalDB, err = testdb.Start(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	if err := approvalDB.Close(context.Background()); err != nil && code == 0 {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	os.Exit(code)
}

type approvalFixture struct {
	store     *store.Store
	authz     *authorization.Service
	service   *Service
	sessions  *session.Service
	spaceID   string
	ownerID   string
	agentID   string
	sessionID string
}

func newApprovalFixture(t *testing.T) approvalFixture {
	t.Helper()
	ctx := context.Background()
	database, err := approvalDB.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	st, err := store.Open(ctx, database.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO users (id, email, email_normalized, password_hash, status, email_verified_at)
		VALUES ('usr_approval_owner', 'owner@example.test', 'owner@example.test', 'hash', 'active', now()),
		       ('usr_approval_other', 'other@example.test', 'other@example.test', 'hash', 'active', now())
	`); err != nil {
		t.Fatal(err)
	}
	authz := &authorization.Service{Store: st}
	space, owner, err := authz.CreateSpace(ctx, "usr_approval_owner", "Approval Test", "approval-test")
	if err != nil {
		t.Fatal(err)
	}
	agents := &agent.Service{Store: st}
	created, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, CreatedByUser: "usr_approval_owner", Name: "Approval Agent", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
		VALUES ('grt_approval_agent', $1, '["auth.bindings:manage"]'::jsonb, $2, 'space', $1, $3)
	`, space.ID, created.ID, owner.ID); err != nil {
		t.Fatal(err)
	}
	signer, err := security.GenerateSigner("https://auth.test")
	if err != nil {
		t.Fatal(err)
	}
	sessions := &session.Service{
		Store: st, Signer: signer, HMACKeys: [][]byte{[]byte(strings.Repeat("h", 32))},
		Settings: func(context.Context) (session.Settings, error) {
			return session.Settings{AccessTTL: time.Minute, RefreshTTL: time.Hour, RefreshIdleTTL: 30 * time.Minute}, nil
		},
	}
	tokens, err := sessions.CreateForMember(ctx, "usr_approval_owner", owner.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{Store: st, Authorization: authz, StepUp: sessions}
	return approvalFixture{store: st, authz: authz, service: service, sessions: sessions, spaceID: space.ID, ownerID: owner.ID, agentID: created.ID, sessionID: tokens.SessionID}
}

func (f approvalFixture) resource(id string) Resource {
	return Resource{Type: "invoice", ID: id, SpaceID: f.spaceID}
}

func (f approvalFixture) check(id string) authorization.CheckRequest {
	return authorization.CheckRequest{MemberID: f.agentID, Permission: "auth.bindings:manage", ResourceSpace: f.spaceID}
}

func (f approvalFixture) stepUpContext(t *testing.T, approvalID, operation string) context.Context {
	t.Helper()
	digest, err := stepup.DigestValue(map[string]any{"approval_id": approvalID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Pool.Exec(context.Background(), `
		UPDATE sessions SET step_up_operation = $2, step_up_digest = $3, step_up_method = 'totp',
		    step_up_expires_at = now() + interval '5 minutes' WHERE id = $1
	`, f.sessionID, operation, digest); err != nil {
		t.Fatal(err)
	}
	return session.WithStepUpRequirement(context.Background(), session.StepUpRequirement{SessionID: f.sessionID, Operation: operation, Digest: digest})
}

func approvalCode(err error) string {
	var public *apierr.Error
	if errors.As(err, &public) {
		return public.Code
	}
	return ""
}

func TestBusinessApprovalInboxStepUpAndSingleUse(t *testing.T) {
	ctx := context.Background()
	f := newApprovalFixture(t)
	before, _, err := f.authz.CheckBusiness(ctx, f.check("inv_1"), "invoice", "inv_1")
	if err != nil || before.Code != "APPROVAL_REQUIRED" {
		t.Fatalf("unapproved decision = %+v, %v", before, err)
	}
	digest := sha256.Sum256([]byte("invoice approval request"))
	created, err := f.service.CreateBusiness(ctx, "key_approval_test", f.agentID, "auth.bindings:manage", f.resource("inv_1"), digest[:], "Approve invoice 1")
	if err != nil || created.Status != "pending" || created.ID == "" {
		t.Fatalf("approval creation = %+v, %v", created, err)
	}
	ownerInbox, err := f.service.ListForUser(ctx, "usr_approval_owner")
	if err != nil || len(ownerInbox) != 1 || ownerInbox[0].ID != created.ID {
		t.Fatalf("owner inbox = %+v, %v", ownerInbox, err)
	}
	otherInbox, err := f.service.ListForUser(ctx, "usr_approval_other")
	if err != nil || len(otherInbox) != 0 {
		t.Fatalf("unbound user inbox = %+v, %v", otherInbox, err)
	}
	pending, _, err := f.authz.CheckBusiness(ctx, f.check("inv_1"), "invoice", "inv_1")
	if err != nil || pending.Code != "APPROVAL_PENDING" {
		t.Fatalf("pending decision = %+v, %v", pending, err)
	}
	proof := f.stepUpContext(t, created.ID, "approvals.approve")
	if _, err := f.service.Decide(proof, "usr_approval_other", created.ID, true); approvalCode(err) != "PERMISSION_DENIED" {
		t.Fatalf("unbound approver error = %v", err)
	}
	decided, err := f.service.Decide(proof, "usr_approval_owner", created.ID, true)
	if err != nil || decided.Status != "approved" {
		t.Fatalf("approval decision = %+v, %v", decided, err)
	}
	var approvedExpiry time.Time
	if err := f.store.Pool.QueryRow(ctx, `SELECT approved_expires_at FROM approval_requests WHERE id = $1`, created.ID).Scan(&approvedExpiry); err != nil {
		t.Fatal(err)
	}
	if remaining := time.Until(approvedExpiry); remaining < 14*time.Minute || remaining > 15*time.Minute+time.Minute {
		t.Fatalf("approval remaining life = %s", remaining)
	}
	wrong, _, err := f.authz.CheckBusiness(ctx, f.check("inv_2"), "invoice", "inv_2")
	if err != nil || wrong.Code != "APPROVAL_REQUIRED" {
		t.Fatalf("different resource decision = %+v, %v", wrong, err)
	}
	const attempts = 4
	results := make(chan engine.Decision, attempts)
	errors := make(chan error, attempts)
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			decision, _, checkErr := f.authz.CheckBusiness(ctx, f.check("inv_1"), "invoice", "inv_1")
			results <- decision
			errors <- checkErr
		}()
	}
	wg.Wait()
	close(results)
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	successes := 0
	for decision := range results {
		if decision.Effect == engine.Allow {
			successes++
		} else if decision.Code != "APPROVAL_REQUIRED" {
			t.Fatalf("unexpected concurrent decision = %+v", decision)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent approval uses = %d, want 1", successes)
	}
}

func TestBusinessApprovalRejectionAndAuditRollback(t *testing.T) {
	ctx := context.Background()
	f := newApprovalFixture(t)
	digest := sha256.Sum256([]byte("invoice rejection request"))
	created, err := f.service.CreateBusiness(ctx, "key_approval_test", f.agentID, "auth.bindings:manage", f.resource("inv_3"), digest[:], "Reject invoice 3")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Pool.Exec(ctx, `
		CREATE FUNCTION reject_approval_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action = 'approval.rejected' THEN RAISE EXCEPTION 'audit failed'; END IF; RETURN NEW; END;
		$$;
		CREATE TRIGGER reject_approval_audit BEFORE INSERT ON audit_logs
		FOR EACH ROW EXECUTE FUNCTION reject_approval_audit()
	`); err != nil {
		t.Fatal(err)
	}
	proof := f.stepUpContext(t, created.ID, "approvals.reject")
	if _, err := f.service.Decide(proof, "usr_approval_owner", created.ID, false); err == nil {
		t.Fatal("rejection succeeded despite audit failure")
	}
	var status string
	if err := f.store.Pool.QueryRow(ctx, `SELECT status FROM approval_requests WHERE id = $1`, created.ID).Scan(&status); err != nil || status != "pending" {
		t.Fatalf("audit failure left status %q: %v", status, err)
	}
	if _, err := f.store.Pool.Exec(ctx, `DROP TRIGGER reject_approval_audit ON audit_logs; DROP FUNCTION reject_approval_audit()`); err != nil {
		t.Fatal(err)
	}
	decided, err := f.service.Decide(proof, "usr_approval_owner", created.ID, false)
	if err != nil || decided.Status != "rejected" {
		t.Fatalf("rejection after retry = %+v, %v", decided, err)
	}
	decision, _, err := f.authz.CheckBusiness(ctx, f.check("inv_3"), "invoice", "inv_3")
	if err != nil || decision.Code != "APPROVAL_REJECTED" {
		t.Fatalf("rejected decision = %+v, %v", decision, err)
	}
	if _, err := f.service.Decide(proof, "usr_approval_owner", created.ID, true); approvalCode(err) != "CONFLICT" {
		t.Fatalf("second decision error = %v", err)
	}
}

func TestBusinessApprovalRechecksOwnerAndExpiry(t *testing.T) {
	ctx := context.Background()
	f := newApprovalFixture(t)
	digest := sha256.Sum256([]byte("owner and expiry check"))
	created, err := f.service.CreateBusiness(ctx, "key_approval_test", f.agentID,
		"auth.bindings:manage", f.resource("inv_owner"), digest[:], "Check owner")
	if err != nil {
		t.Fatal(err)
	}
	proof := f.stepUpContext(t, created.ID, "approvals.approve")
	if _, err := f.service.Decide(proof, "usr_approval_owner", created.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Pool.Exec(ctx, `UPDATE members SET status = 'suspended' WHERE id = $1`, f.ownerID); err != nil {
		t.Fatal(err)
	}
	decision, _, err := f.authz.CheckBusiness(ctx, f.check("inv_owner"), "invoice", "inv_owner")
	if err != nil || decision.Code != "OWNER_INACTIVE" {
		t.Fatalf("inactive owner decision = %+v, %v", decision, err)
	}
	if _, err := f.store.Pool.Exec(ctx, `UPDATE members SET status = 'active' WHERE id = $1`, f.ownerID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, f.ownerID); err != nil {
		t.Fatal(err)
	}
	decision, _, err = f.authz.CheckBusiness(ctx, f.check("inv_owner"), "invoice", "inv_owner")
	if err != nil || decision.Code != "OWNER_ENVELOPE_EXCLUDED" {
		t.Fatalf("owner without grant decision = %+v, %v", decision, err)
	}
	if _, err := f.store.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = NULL WHERE grantee_member_id = $1`, f.ownerID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Pool.Exec(ctx, `UPDATE approval_requests SET approved_expires_at = now() - interval '1 second' WHERE id = $1`, created.ID); err != nil {
		t.Fatal(err)
	}
	decision, _, err = f.authz.CheckBusiness(ctx, f.check("inv_owner"), "invoice", "inv_owner")
	if err != nil || decision.Code != "APPROVAL_REQUIRED" {
		t.Fatalf("expired approval decision = %+v, %v", decision, err)
	}
}

func TestBusinessApprovalConsumptionRollsBackOnAuditFailure(t *testing.T) {
	ctx := context.Background()
	f := newApprovalFixture(t)
	digest := sha256.Sum256([]byte("consumption audit check"))
	created, err := f.service.CreateBusiness(ctx, "key_approval_test", f.agentID,
		"auth.bindings:manage", f.resource("inv_audit"), digest[:], "Check audit")
	if err != nil {
		t.Fatal(err)
	}
	proof := f.stepUpContext(t, created.ID, "approvals.approve")
	if _, err := f.service.Decide(proof, "usr_approval_owner", created.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Pool.Exec(ctx, `
		CREATE FUNCTION reject_approval_consumption_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action = 'approval.consume' THEN RAISE EXCEPTION 'audit failed'; END IF; RETURN NEW; END;
		$$;
		CREATE TRIGGER reject_approval_consumption_audit BEFORE INSERT ON audit_logs
		FOR EACH ROW EXECUTE FUNCTION reject_approval_consumption_audit()
	`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.authz.CheckBusiness(ctx, f.check("inv_audit"), "invoice", "inv_audit"); err == nil {
		t.Fatal("approval was consumed despite audit failure")
	}
	var status string
	if err := f.store.Pool.QueryRow(ctx, `SELECT status FROM approval_requests WHERE id = $1`, created.ID).Scan(&status); err != nil || status != "approved" {
		t.Fatalf("audit failure left status %q: %v", status, err)
	}
}

func TestBusinessApprovalReasonLimitCountsUnicodeCharacters(t *testing.T) {
	f := newApprovalFixture(t)
	digest := sha256.Sum256([]byte("unicode reason"))
	_, err := f.service.CreateBusiness(context.Background(), "key_approval_test", f.agentID,
		"auth.bindings:manage", f.resource("inv_unicode"), digest[:], strings.Repeat("理", 2000))
	if err != nil {
		t.Fatalf("2000 character reason rejected: %v", err)
	}
	_, err = f.service.CreateBusiness(context.Background(), "key_approval_test", f.agentID,
		"auth.bindings:manage", f.resource("inv_unicode_2"), digest[:], strings.Repeat("理", 2001))
	if approvalCode(err) != "VALIDATION_FAILED" {
		t.Fatalf("2001 character reason error = %v", err)
	}
}
