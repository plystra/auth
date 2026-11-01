package invitation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/mail"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/space"
	"github.com/plystra/auth/internal/store"
	"github.com/plystra/auth/internal/testdb"
)

var invitationDB *testdb.Harness

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var err error
	invitationDB, err = testdb.Start(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	if err := invitationDB.Close(context.Background()); err != nil && code == 0 {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	os.Exit(code)
}

func TestInvitationTokensAreHashedSingleUseAndExpire(t *testing.T) {
	ctx := context.Background()
	st := newInvitationStore(t)
	svc := &Service{Store: st}

	inv, raw, err := svc.Create(ctx, CreateInput{SpaceID: "spc_01h00000000000000000000000", Email: "  Invitee@Example.Test ", MemberID: "mem_invitation_target"})
	if err != nil {
		t.Fatal(err)
	}
	if inv.EmailNormalized != "invitee@example.test" {
		t.Fatalf("normalized email = %q", inv.EmailNormalized)
	}
	var stored []byte
	if err := st.Pool.QueryRow(ctx, `SELECT token_hash FROM invitation_tokens WHERE id = $1`, inv.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if string(stored) == raw || len(stored) != 32 {
		t.Fatal("invitation token was stored in plaintext or with the wrong digest length")
	}

	consumed, err := svc.Consume(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	if consumed.ID != inv.ID || consumed.ConsumedAt == nil {
		t.Fatalf("consumed invitation = %+v", consumed)
	}
	if _, err := svc.Consume(ctx, raw); !hasCode(err, "invalid_grant") {
		t.Fatalf("second consume error = %v, want invalid_grant", err)
	}

	_, expiredRaw, err := svc.Create(ctx, CreateInput{SpaceID: "spc_01h00000000000000000000000", Email: "expired@example.test", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE invitation_tokens SET expires_at = now() - interval '1 second' WHERE email_normalized = 'expired@example.test'`); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Consume(ctx, expiredRaw); !hasCode(err, "invalid_grant") {
		t.Fatalf("expired consume error = %v, want invalid_grant", err)
	}
}

func TestInvitationTokenConcurrentConsumptionIsSingleUse(t *testing.T) {
	ctx := context.Background()
	st := newInvitationStore(t)
	svc := &Service{Store: st}
	_, raw, err := svc.Create(ctx, CreateInput{SpaceID: "spc_01h00000000000000000000000", Email: "race@example.test"})
	if err != nil {
		t.Fatal(err)
	}

	const attempts = 8
	var wg sync.WaitGroup
	results := make(chan error, attempts)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, consumeErr := svc.Consume(ctx, raw)
			results <- consumeErr
		}()
	}
	wg.Wait()
	close(results)

	var successes, invalid int
	for err := range results {
		switch {
		case err == nil:
			successes++
		case hasCode(err, "invalid_grant"):
			invalid++
		default:
			t.Fatalf("unexpected concurrent consume error: %v", err)
		}
	}
	if successes != 1 || invalid != attempts-1 {
		t.Fatalf("concurrent consume results: successes=%d invalid=%d", successes, invalid)
	}
}

func TestInvitationAcceptanceRequiresVerifiedMatchingAccountAndActiveSpace(t *testing.T) {
	ctx := context.Background()
	st := newInvitationStore(t)
	svc := &Service{Store: st}
	const userID = "usr_invitation_accept"
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ($1, 'invitee@example.test', 'invitee@example.test', 'hash', 'active')
	`, userID); err != nil {
		t.Fatal(err)
	}
	_, raw, err := svc.Create(ctx, CreateInput{SpaceID: "spc_01h00000000000000000000000", Email: "invitee@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AcceptVerifiedUser(ctx, raw, userID); !hasCode(err, "EMAIL_VERIFICATION_REQUIRED") {
		t.Fatalf("unverified account acceptance = %v", err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE users SET email_verified_at = now() WHERE id = $1`, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE users SET email_normalized = 'different@example.test' WHERE id = $1`, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AcceptVerifiedUser(ctx, raw, userID); !hasCode(err, "invalid_grant") {
		t.Fatalf("mismatched email acceptance = %v", err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE users SET email_normalized = 'invitee@example.test' WHERE id = $1`, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE spaces SET status = 'suspended' WHERE id = 'spc_01h00000000000000000000000'`); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AcceptVerifiedUser(ctx, raw, userID); !hasCode(err, "SPACE_INACTIVE") {
		t.Fatalf("suspended Space acceptance = %v", err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE spaces SET status = 'active' WHERE id = 'spc_01h00000000000000000000000'`); err != nil {
		t.Fatal(err)
	}
	accepted, err := svc.AcceptVerifiedUser(ctx, raw, userID)
	if err != nil || accepted.MemberID == "" {
		t.Fatalf("valid invitation was consumed by a rejected attempt: accepted=%+v err=%v", accepted, err)
	}
	existing, existingRaw, err := svc.Create(ctx, CreateInput{
		SpaceID: "spc_01h00000000000000000000000", Email: "invitee@example.test", MemberID: "mem_invitation_target",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AcceptVerifiedUser(ctx, existingRaw, userID); !hasCode(err, "AUTHORITY_DELTA_NOT_COVERED") {
		t.Fatalf("existing-member invitation bypassed delta coverage: %v", err)
	}
	var consumed int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM invitation_tokens WHERE id = $1 AND consumed_at IS NOT NULL`, existing.ID).Scan(&consumed); err != nil {
		t.Fatal(err)
	}
	if consumed != 0 {
		t.Fatal("rejected existing-member invitation was consumed")
	}
}

func TestInvitationAcceptanceRollsBackOnAuditFailure(t *testing.T) {
	ctx := context.Background()
	st := newInvitationStore(t)
	svc := &Service{Store: st}
	const userID = "usr_invitation_rollback"
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO users (id, email, email_normalized, password_hash, status, email_verified_at)
		VALUES ($1, 'rollback@example.test', 'rollback@example.test', 'hash', 'active', now())
	`, userID); err != nil {
		t.Fatal(err)
	}
	inv, raw, err := svc.Create(ctx, CreateInput{SpaceID: "spc_01h00000000000000000000000", Email: "rollback@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		CREATE FUNCTION reject_invitation_acceptance_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'invitation acceptance audit rejected by test'; END;
		$$;
		CREATE TRIGGER test_reject_invitation_acceptance_audit BEFORE INSERT ON audit_logs
		FOR EACH ROW EXECUTE FUNCTION reject_invitation_acceptance_audit();
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AcceptVerifiedUser(ctx, raw, userID); err == nil {
		t.Fatal("acceptance succeeded despite audit failure")
	}
	var members, consumed int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM members WHERE name = 'rollback@example.test'`).Scan(&members); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM invitation_tokens WHERE id = $1 AND consumed_at IS NOT NULL`, inv.ID).Scan(&consumed); err != nil {
		t.Fatal(err)
	}
	if members != 0 || consumed != 0 {
		t.Fatalf("audit failure left members=%d consumed=%d", members, consumed)
	}
}

type registrationMailSender struct{ body chan string }

func (s *registrationMailSender) Send(_ context.Context, _, _, body string) error {
	s.body <- body
	return nil
}

func newInvitedRegistrationServices(t *testing.T, st *store.Store) (*Service, *account.Service, *registrationMailSender) {
	t.Helper()
	ctx := context.Background()
	if _, err := st.Pool.Exec(ctx, `UPDATE instance_settings SET registration_mode = 'invite_only'`); err != nil {
		t.Fatal(err)
	}
	sender := &registrationMailSender{body: make(chan string, 1)}
	mailer, err := mail.New(secret.New(strings.Repeat("d", 32)), st.Jobs, sender)
	if err != nil {
		t.Fatal(err)
	}
	accounts := &account.Service{Store: st, Passwords: security.DefaultPasswordHasher(), Settings: &space.Service{Store: st}, Mailer: mailer}
	invites := &Service{Store: st, Accounts: accounts}
	accounts.Invitations = invites
	return invites, accounts, sender
}

func deliveredVerificationToken(t *testing.T, st *store.Store, accounts *account.Service, sender *registrationMailSender) string {
	t.Helper()
	var args []byte
	if err := st.Pool.QueryRow(context.Background(), `SELECT args FROM river_job WHERE kind = 'email_delivery'`).Scan(&args); err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Ciphertext []byte `json:"ciphertext"`
	}
	if err := json.Unmarshal(args, &payload); err != nil {
		t.Fatal(err)
	}
	if err := accounts.Mailer.DeliverEmail(context.Background(), payload.Ciphertext); err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(strings.TrimPrefix(<-sender.body, "Enter this verification token in Plystra Auth: "))
}

func TestInvitedRegistrationRechecksExpiryAndSpaceAtEmailVerification(t *testing.T) {
	ctx := context.Background()
	st := newInvitationStore(t)
	invites, accounts, sender := newInvitedRegistrationServices(t, st)
	created, raw, err := invites.Create(ctx, CreateInput{SpaceID: account.DefaultSpaceID, Email: "retry@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := invites.RegisterNewUser(ctx, raw, "different@example.test", "a sufficiently long password"); !hasCode(err, "invalid_grant") {
		t.Fatalf("mismatched email registration = %v", err)
	}
	if _, err := invites.RegisterNewUser(ctx, raw, "retry@example.test", "a sufficiently long password"); err != nil {
		t.Fatal(err)
	}
	verification := deliveredVerificationToken(t, st, accounts, sender)
	accounts.Invitations = nil
	if err := accounts.VerifyEmail(ctx, verification); !hasCode(err, "UNAVAILABLE") {
		t.Fatalf("verification without invitation finalizer = %v", err)
	}
	accounts.Invitations = invites
	if _, err := st.Pool.Exec(ctx, `UPDATE invitation_tokens SET expires_at = now() - interval '1 second' WHERE id = $1`, created.ID); err != nil {
		t.Fatal(err)
	}
	if err := accounts.VerifyEmail(ctx, verification); !hasCode(err, "invalid_grant") {
		t.Fatalf("expired invitation verification = %v", err)
	}
	var status string
	if err := st.Pool.QueryRow(ctx, `SELECT status FROM users WHERE email_normalized = 'retry@example.test'`).Scan(&status); err != nil || status != "pending" {
		t.Fatalf("expired invitation changed account status to %q: %v", status, err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE invitation_tokens SET expires_at = now() + interval '1 hour' WHERE id = $1`, created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE spaces SET status = 'suspended' WHERE id = $1`, account.DefaultSpaceID); err != nil {
		t.Fatal(err)
	}
	if err := accounts.VerifyEmail(ctx, verification); !hasCode(err, "SPACE_INACTIVE") {
		t.Fatalf("suspended Space verification = %v", err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE spaces SET status = 'active' WHERE id = $1`, account.DefaultSpaceID); err != nil {
		t.Fatal(err)
	}
	if err := accounts.VerifyEmail(ctx, verification); err != nil {
		t.Fatalf("valid retry after rejected verification = %v", err)
	}
}

func TestInvitedVerificationAuditFailureRollsBackAcceptance(t *testing.T) {
	ctx := context.Background()
	st := newInvitationStore(t)
	invites, accounts, sender := newInvitedRegistrationServices(t, st)
	created, raw, err := invites.Create(ctx, CreateInput{SpaceID: account.DefaultSpaceID, Email: "audit-invite@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := invites.RegisterNewUser(ctx, raw, "audit-invite@example.test", "a sufficiently long password"); err != nil {
		t.Fatal(err)
	}
	verification := deliveredVerificationToken(t, st, accounts, sender)
	if _, err := st.Pool.Exec(ctx, `
		CREATE FUNCTION reject_invited_acceptance_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action = 'invitation.accept' THEN RAISE EXCEPTION 'test audit rejection'; END IF; RETURN NEW; END;
		$$;
		CREATE TRIGGER test_reject_invited_acceptance_audit BEFORE INSERT ON audit_logs
		FOR EACH ROW EXECUTE FUNCTION reject_invited_acceptance_audit();
	`); err != nil {
		t.Fatal(err)
	}
	if err := accounts.VerifyEmail(ctx, verification); err == nil {
		t.Fatal("invitation acceptance survived audit failure")
	}
	var status string
	if err := st.Pool.QueryRow(ctx, `SELECT status FROM users WHERE email_normalized = 'audit-invite@example.test'`).Scan(&status); err != nil || status != "pending" {
		t.Fatalf("audit failure changed account status to %q: %v", status, err)
	}
	var consumed, bindings int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM invitation_tokens WHERE id = $1 AND consumed_at IS NOT NULL`, created.ID).Scan(&consumed); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM user_members um JOIN users u ON u.id = um.user_id WHERE u.email_normalized = 'audit-invite@example.test'`).Scan(&bindings); err != nil {
		t.Fatal(err)
	}
	if consumed != 0 || bindings != 0 {
		t.Fatalf("audit failure left invitation consumed=%d bindings=%d", consumed, bindings)
	}
}

func TestInvitedRegistrationHonorsPolicyAndConcurrentEmailUniqueness(t *testing.T) {
	ctx := context.Background()
	st := newInvitationStore(t)
	invites, _, _ := newInvitedRegistrationServices(t, st)
	_, raw, err := invites.Create(ctx, CreateInput{SpaceID: account.DefaultSpaceID, Email: "concurrent-invite@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE instance_settings SET registration_mode = 'closed'`); err != nil {
		t.Fatal(err)
	}
	if _, err := invites.RegisterNewUser(ctx, raw, "concurrent-invite@example.test", "a sufficiently long password"); !hasCode(err, "forbidden") {
		t.Fatalf("closed registration policy = %v", err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE instance_settings SET registration_mode = 'invite_only'`); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	var group sync.WaitGroup
	for i := 0; i < 2; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			_, registerErr := invites.RegisterNewUser(ctx, raw, "concurrent-invite@example.test", "a sufficiently long password")
			results <- registerErr
		}()
	}
	group.Wait()
	close(results)
	var success, conflict int
	for err := range results {
		switch {
		case err == nil:
			success++
		case hasCode(err, "conflict"):
			conflict++
		default:
			t.Fatalf("concurrent invited registration = %v", err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("concurrent invited registration: success=%d conflict=%d", success, conflict)
	}
	var users, jobs int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE email_normalized = 'concurrent-invite@example.test'`).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM river_job WHERE kind = 'email_delivery'`).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if users != 1 || jobs != 1 {
		t.Fatalf("concurrent invited registration left users=%d jobs=%d", users, jobs)
	}
}

func TestInvitedRegistrationAuditFailureRollsBackAccountAndMail(t *testing.T) {
	ctx := context.Background()
	st := newInvitationStore(t)
	invites, _, _ := newInvitedRegistrationServices(t, st)
	created, raw, err := invites.Create(ctx, CreateInput{SpaceID: account.DefaultSpaceID, Email: "registration-audit@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		CREATE FUNCTION reject_invited_registration_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action = 'auth.register' THEN RAISE EXCEPTION 'test audit rejection'; END IF; RETURN NEW; END;
		$$;
		CREATE TRIGGER test_reject_invited_registration_audit BEFORE INSERT ON audit_logs
		FOR EACH ROW EXECUTE FUNCTION reject_invited_registration_audit();
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := invites.RegisterNewUser(ctx, raw, "registration-audit@example.test", "a sufficiently long password"); err == nil {
		t.Fatal("invited registration survived audit failure")
	}
	var users, pending, jobs, consumed int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE email_normalized = 'registration-audit@example.test'`).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM pending_invitation_registrations WHERE invitation_id = $1`, created.ID).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM river_job WHERE kind = 'email_delivery'`).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM invitation_tokens WHERE id = $1 AND consumed_at IS NOT NULL`, created.ID).Scan(&consumed); err != nil {
		t.Fatal(err)
	}
	if users != 0 || pending != 0 || jobs != 0 || consumed != 0 {
		t.Fatalf("audit failure left users=%d pending=%d jobs=%d consumed=%d", users, pending, jobs, consumed)
	}
}

func newInvitationStore(t *testing.T) *store.Store {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := invitationDB.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close(context.Background()) })
	st, err := store.Open(ctx, db.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Pool.Exec(ctx, `INSERT INTO members (id, space_id, name, type) VALUES ('mem_invitation_target', 'spc_01h00000000000000000000000', 'Invitation target', 'human')`); err != nil {
		t.Fatal(err)
	}
	return st
}

func hasCode(err error, code string) bool {
	var e *apierr.Error
	return errors.As(err, &e) && e.Code == code
}
