package operator

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/factor"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/store"
	"github.com/plystra/auth/internal/testdb"
	"github.com/pquerna/otp/totp"
)

var operatorDB *testdb.Harness

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var err error
	operatorDB, err = testdb.Start(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	if err := operatorDB.Close(context.Background()); err != nil && code == 0 {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	os.Exit(code)
}

func TestOperatorSignInRequiresMFAAndUsesDocumentedSessionDurations(t *testing.T) {
	ctx := context.Background()
	st := newOperatorStore(t)
	passwords := security.DefaultPasswordHasher()
	hash, err := passwords.Hash("operator-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ('usr_operator_mfa', 'operator-mfa@example.test', 'operator-mfa@example.test', $1, 'active')
	`, hash); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO operators (user_id, capabilities) VALUES ('usr_operator_mfa', '["*"]'::jsonb)`); err != nil {
		t.Fatal(err)
	}
	factors := &factor.Service{Store: st, DataKey: secret.New(strings.Repeat("d", 32))}
	enrollment, err := factors.BeginTOTP(ctx, "usr_operator_mfa", "operator-mfa@example.test")
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(enrollment.Secret.Value(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	svc, err := New(st, factors, [][]byte{[]byte(strings.Repeat("h", 32))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SignIn(ctx, "operator-mfa@example.test", "operator-password", "000000", net.ParseIP("192.0.2.10"), "test"); err == nil {
		t.Fatal("operator sign-in succeeded without a valid MFA code")
	}
	session, err := svc.SignIn(ctx, "operator-mfa@example.test", "operator-password", code, net.ParseIP("192.0.2.10"), "test")
	if err != nil {
		t.Fatal(err)
	}
	var created, access, idle, absolute time.Time
	if err := st.Pool.QueryRow(ctx, `SELECT created_at, access_expires_at, idle_expires_at, expires_at FROM operator_sessions WHERE id = $1`, session.ID).Scan(&created, &access, &idle, &absolute); err != nil {
		t.Fatal(err)
	}
	assertDurationNear(t, access.Sub(created), 10*time.Minute)
	assertDurationNear(t, idle.Sub(created), 30*time.Minute)
	assertDurationNear(t, absolute.Sub(created), 8*time.Hour)
}

func TestOperatorCapabilitySubsetAndLastFullOperatorProtection(t *testing.T) {
	ctx := context.Background()
	st := newOperatorStore(t)
	insertOperator(t, st, "usr_operator_owner", "owner", `["ops:operators:manage"]`)
	insertOperator(t, st, "usr_operator_target", "target", `["ops:operators:read"]`)
	key := []byte(strings.Repeat("h", 32))
	raw := insertOperatorSession(t, st, "usr_operator_owner", key, nil)
	svc, err := New(st, &factor.Service{Store: st, DataKey: secret.New(strings.Repeat("d", 32))}, [][]byte{key})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.UpdateCapabilities(ctx, raw, "usr_operator_target", []string{"*"}, nil); err == nil {
		t.Fatal("operator received capabilities outside the initiator subset")
	} else {
		assertOperatorError(t, err, "PERMISSION_DENIED")
	}

	st2 := newOperatorStore(t)
	insertOperator(t, st2, "usr_operator_last", "last", `["*"]`)
	raw2 := insertOperatorSession(t, st2, "usr_operator_last", key, nil)
	svc2, err := New(st2, &factor.Service{Store: st2, DataKey: secret.New(strings.Repeat("d", 32))}, [][]byte{key})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc2.Disable(ctx, raw2, "usr_operator_last", nil); err == nil {
		t.Fatal("the last full-capability operator was disabled")
	} else {
		assertOperatorError(t, err, "CONFLICT")
	}
}

func TestOperatorBootstrapOnlyRunsWithoutExistingOperators(t *testing.T) {
	ctx := context.Background()
	st := newOperatorStore(t)
	hash, err := security.DefaultPasswordHasher().Hash("bootstrap-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ('usr_operator_bootstrap', 'bootstrap@example.test', 'bootstrap@example.test', $1, 'active')
	`, hash); err != nil {
		t.Fatal(err)
	}
	key := []byte(strings.Repeat("h", 32))
	svc, err := New(st, &factor.Service{Store: st, DataKey: secret.New(strings.Repeat("d", 32))}, [][]byte{key})
	if err != nil {
		t.Fatal(err)
	}
	result, err := svc.Bootstrap(ctx, "usr_operator_bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	if result.UserID != "usr_operator_bootstrap" || !strings.HasPrefix(result.APIKey, "ply_sk_") || result.TOTPSecret == "" {
		t.Fatalf("bootstrap result = %+v, want user, API key, and TOTP enrollment", result)
	}
	parts := strings.SplitN(result.APIKey, ".", 2)
	var storedHash []byte
	var hashScheme string
	if err := st.Pool.QueryRow(ctx, `SELECT secret_hash, hash_scheme FROM api_keys WHERE prefix = $1`, parts[0]).Scan(&storedHash, &hashScheme); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(parts[1]))
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(digest[:])
	if hashScheme != "hmac_sha256" || !hmac.Equal(storedHash, mac.Sum(nil)) {
		t.Fatal("operator bootstrap API key was not stored as an HMAC digest")
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM operators`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("operator count = %d, want 1", count)
	}
	if _, err := svc.Bootstrap(ctx, "usr_operator_bootstrap"); err == nil {
		t.Fatal("bootstrap succeeded after an operator already existed")
	} else {
		assertOperatorError(t, err, "CONFLICT")
	}
}

func TestOperatorAndMemberIdentitiesAreMutuallyExclusive(t *testing.T) {
	ctx := context.Background()
	st := newOperatorStore(t)
	if err := insertAccountUserForOperator(ctx, st, "usr_member_identity", "member-identity@example.test", "active"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO members (id, space_id, name, kind, type, binding_policy, status)
		VALUES ('mem_operator_exclusion', 'spc_01h00000000000000000000000', 'Bound member', 'user', 'human', 'single', 'active')
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO user_members (user_id, member_id) VALUES ('usr_member_identity', 'mem_operator_exclusion')`); err != nil {
		t.Fatal(err)
	}
	svc, err := New(st, &factor.Service{Store: st, DataKey: secret.New(strings.Repeat("d", 32))}, [][]byte{[]byte(strings.Repeat("h", 32))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Bootstrap(ctx, "usr_member_identity"); err == nil {
		t.Fatal("bootstrap promoted an active member binding to an operator")
	} else {
		assertOperatorError(t, err, "CONFLICT")
	}

	if err := insertAccountUserForOperator(ctx, st, "usr_operator_identity", "operator-identity@example.test", "active"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO operators (user_id, capabilities) VALUES ('usr_operator_identity', '["*"]'::jsonb)`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO members (id, space_id, name, kind, type, binding_policy, status)
		VALUES ('mem_operator_exclusion_reverse', 'spc_01h00000000000000000000000', 'Operator member', 'user', 'human', 'single', 'active')
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO user_members (user_id, member_id) VALUES ('usr_operator_identity', 'mem_operator_exclusion_reverse')`); err == nil {
		t.Fatal("database allowed an operator to receive an active member binding")
	}
}

func TestOperatorStepUpBindsRequestDigestAndIsSingleUse(t *testing.T) {
	ctx := context.Background()
	st := newOperatorStore(t)
	insertOperator(t, st, "usr_operator_stepup", "stepup", `["*"]`)
	insertOperator(t, st, "usr_operator_stepup_peer", "stepup-peer", `["*"]`)
	key := []byte(strings.Repeat("h", 32))
	digest := sha256.Sum256([]byte(`{"user_id":"usr_operator_stepup","capabilities":["ops:operators:manage"]}`))
	raw := insertOperatorSession(t, st, "usr_operator_stepup", key, &digest)
	svc, err := New(st, &factor.Service{Store: st, DataKey: secret.New(strings.Repeat("d", 32))}, [][]byte{key})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.UpdateCapabilities(ctx, raw, "usr_operator_stepup", []string{"ops:operators:manage"}, digest[:]); err != nil {
		t.Fatal(err)
	}
	if err := svc.UpdateCapabilities(ctx, raw, "usr_operator_stepup", []string{"ops:operators:manage"}, digest[:]); err == nil {
		t.Fatal("operator step-up digest was reusable")
	} else {
		assertOperatorError(t, err, "STEP_UP_REQUIRED")
	}
}

func TestOperatorMutationRollsBackWhenAuditFails(t *testing.T) {
	ctx := context.Background()
	st := newOperatorStore(t)
	insertOperator(t, st, "usr_operator_audit_owner", "audit-owner", `["ops:operators:manage"]`)
	insertOperator(t, st, "usr_operator_audit_target", "audit-target", `["ops:operators:read"]`)
	key := []byte(strings.Repeat("h", 32))
	raw := insertOperatorSession(t, st, "usr_operator_audit_owner", key, nil)
	svc, err := New(st, &factor.Service{Store: st, DataKey: secret.New(strings.Repeat("d", 32))}, [][]byte{key})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		CREATE FUNCTION reject_operator_audit_insert() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'operator audit insert rejected by test'; END;
		$$;
		CREATE TRIGGER test_reject_operator_audit BEFORE INSERT ON audit_logs
		FOR EACH ROW EXECUTE FUNCTION reject_operator_audit_insert();
	`); err != nil {
		t.Fatal(err)
	}
	if err := svc.UpdateCapabilities(ctx, raw, "usr_operator_audit_target", []string{"ops:operators:manage"}, nil); err == nil {
		t.Fatal("operator capability update succeeded despite audit failure")
	}
	var capabilities []byte
	if err := st.Pool.QueryRow(ctx, `SELECT capabilities FROM operators WHERE user_id = $1`, "usr_operator_audit_target").Scan(&capabilities); err != nil {
		t.Fatal(err)
	}
	if string(capabilities) != `["ops:operators:read"]` {
		t.Fatalf("operator capabilities changed after audit failure: %s", capabilities)
	}
}

func TestOperatorCanSuspendUserAndRevokeAllCredentials(t *testing.T) {
	ctx := context.Background()
	st := newOperatorStore(t)
	insertOperator(t, st, "usr_status_operator", "status-operator", `["ops:users:manage"]`)
	insertOperator(t, st, "usr_status_target", "status-target", `[]`)
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO sessions (id, user_id, token_hash, expires_at)
		VALUES ('ses_operator_status', 'usr_status_target', decode(repeat('55', 32), 'hex'), now() + interval '1 hour')
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO refresh_tokens (id, session_id, family_id, token_hash, expires_at)
		VALUES ('rft_operator_status', 'ses_operator_status', 'rtf_operator_status', decode(repeat('66', 32), 'hex'), now() + interval '1 hour')
	`); err != nil {
		t.Fatal(err)
	}
	key := []byte(strings.Repeat("h", 32))
	raw := insertOperatorSession(t, st, "usr_status_operator", key, nil)
	svc, err := New(st, &factor.Service{Store: st, DataKey: secret.New(strings.Repeat("d", 32))}, [][]byte{key})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SuspendUser(ctx, raw, "usr_status_target", nil); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := st.Pool.QueryRow(ctx, `SELECT status FROM users WHERE id = 'usr_status_target'`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "suspended" {
		t.Fatalf("user status = %q, want suspended", status)
	}
	var activeSessions, activeRefreshTokens int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE id = 'ses_operator_status' AND revoked_at IS NULL`).Scan(&activeSessions); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM refresh_tokens WHERE id = 'rft_operator_status' AND revoked_at IS NULL`).Scan(&activeRefreshTokens); err != nil {
		t.Fatal(err)
	}
	if activeSessions != 0 || activeRefreshTokens != 0 {
		t.Fatalf("credentials after operator suspension: sessions=%d refresh_tokens=%d", activeSessions, activeRefreshTokens)
	}
}

func TestOperatorCanRequirePasswordResetAndRevokeAllCredentials(t *testing.T) {
	ctx := context.Background()
	st := newOperatorStore(t)
	insertOperator(t, st, "usr_reset_operator", "reset-operator", `["ops:users:manage"]`)
	if err := insertAccountUserForOperator(ctx, st, "usr_reset_target", "reset-target@example.test", "active"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE users SET password_reset_required_at = NULL WHERE id = 'usr_reset_target'`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO sessions (id, user_id, token_hash, expires_at)
		VALUES ('ses_operator_reset', 'usr_reset_target', decode(repeat('77', 32), 'hex'), now() + interval '1 hour')
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO refresh_tokens (id, session_id, family_id, token_hash, expires_at)
		VALUES ('rft_operator_reset', 'ses_operator_reset', 'rtf_operator_reset', decode(repeat('88', 32), 'hex'), now() + interval '1 hour')
	`); err != nil {
		t.Fatal(err)
	}
	key := []byte(strings.Repeat("h", 32))
	raw := insertOperatorSession(t, st, "usr_reset_operator", key, nil)
	svc, err := New(st, &factor.Service{Store: st, DataKey: secret.New(strings.Repeat("d", 32))}, [][]byte{key})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.RequirePasswordReset(ctx, raw, "usr_reset_target", nil); err != nil {
		t.Fatal(err)
	}
	var required bool
	if err := st.Pool.QueryRow(ctx, `SELECT password_reset_required_at IS NOT NULL FROM users WHERE id = 'usr_reset_target'`).Scan(&required); err != nil {
		t.Fatal(err)
	}
	if !required {
		t.Fatal("operator action did not require a password reset")
	}
	var sessions, refreshTokens int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE id = 'ses_operator_reset' AND revoked_at IS NULL`).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM refresh_tokens WHERE id = 'rft_operator_reset' AND revoked_at IS NULL`).Scan(&refreshTokens); err != nil {
		t.Fatal(err)
	}
	if sessions != 0 || refreshTokens != 0 {
		t.Fatalf("credentials after password reset requirement: sessions=%d refresh_tokens=%d", sessions, refreshTokens)
	}
	var audits int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = $1 AND actor_id = $2`, "user.password_reset.require", "usr_reset_operator").Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 1 {
		t.Fatalf("password reset requirement audit count = %d, want 1", audits)
	}
}

func TestOperatorRequirePasswordResetRequiresCapabilityAndStepUp(t *testing.T) {
	ctx := context.Background()
	st := newOperatorStore(t)
	insertOperator(t, st, "usr_reset_no_cap", "reset-no-cap", `["ops:operators:manage"]`)
	if err := insertAccountUserForOperator(ctx, st, "usr_reset_no_cap_target", "reset-no-cap-target@example.test", "active"); err != nil {
		t.Fatal(err)
	}
	key := []byte(strings.Repeat("h", 32))
	raw := insertOperatorSession(t, st, "usr_reset_no_cap", key, nil)
	svc, err := New(st, &factor.Service{Store: st, DataKey: secret.New(strings.Repeat("d", 32))}, [][]byte{key})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.RequirePasswordReset(ctx, raw, "usr_reset_no_cap_target", nil); err == nil {
		t.Fatal("password reset requirement bypassed capability check")
	} else {
		assertOperatorError(t, err, "PERMISSION_DENIED")
	}

	st2 := newOperatorStore(t)
	insertOperator(t, st2, "usr_reset_stepup", "reset-stepup", `["ops:users:manage"]`)
	if err := insertAccountUserForOperator(ctx, st2, "usr_reset_stepup_target", "reset-stepup-target@example.test", "active"); err != nil {
		t.Fatal(err)
	}
	raw2 := insertOperatorSession(t, st2, "usr_reset_stepup", key, nil)
	svc2, err := New(st2, &factor.Service{Store: st2, DataKey: secret.New(strings.Repeat("d", 32))}, [][]byte{key})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(`{"id":"usr_reset_stepup_target"}`))
	if err := svc2.RequirePasswordReset(ctx, raw2, "usr_reset_stepup_target", digest[:]); err == nil {
		t.Fatal("password reset requirement bypassed step-up check")
	} else {
		assertOperatorError(t, err, "STEP_UP_REQUIRED")
	}
}

func TestOperatorRequirePasswordResetRollsBackOnAuditFailure(t *testing.T) {
	ctx := context.Background()
	st := newOperatorStore(t)
	insertOperator(t, st, "usr_reset_audit_operator", "reset-audit-operator", `["ops:users:manage"]`)
	if err := insertAccountUserForOperator(ctx, st, "usr_reset_audit_target", "reset-audit-target@example.test", "active"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO sessions (id, user_id, token_hash, expires_at)
		VALUES ('ses_reset_audit', 'usr_reset_audit_target', decode(repeat('99', 32), 'hex'), now() + interval '1 hour')
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO refresh_tokens (id, session_id, family_id, token_hash, expires_at)
		VALUES ('rft_reset_audit', 'ses_reset_audit', 'rtf_reset_audit', decode(repeat('aa', 32), 'hex'), now() + interval '1 hour')
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		CREATE FUNCTION reject_password_reset_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'password reset audit insert rejected by test'; END;
		$$;
		CREATE TRIGGER test_reject_password_reset_audit BEFORE INSERT ON audit_logs
		FOR EACH ROW EXECUTE FUNCTION reject_password_reset_audit();
	`); err != nil {
		t.Fatal(err)
	}
	key := []byte(strings.Repeat("h", 32))
	raw := insertOperatorSession(t, st, "usr_reset_audit_operator", key, nil)
	svc, err := New(st, &factor.Service{Store: st, DataKey: secret.New(strings.Repeat("d", 32))}, [][]byte{key})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.RequirePasswordReset(ctx, raw, "usr_reset_audit_target", nil); err == nil {
		t.Fatal("password reset requirement succeeded despite audit failure")
	}
	var required bool
	if err := st.Pool.QueryRow(ctx, `SELECT password_reset_required_at IS NOT NULL FROM users WHERE id = 'usr_reset_audit_target'`).Scan(&required); err != nil {
		t.Fatal(err)
	}
	if required {
		t.Fatal("password reset flag changed after audit failure")
	}
	var sessions, refreshTokens int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE id = 'ses_reset_audit' AND revoked_at IS NULL`).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM refresh_tokens WHERE id = 'rft_reset_audit' AND revoked_at IS NULL`).Scan(&refreshTokens); err != nil {
		t.Fatal(err)
	}
	if sessions != 1 || refreshTokens != 1 {
		t.Fatalf("credentials changed after audit failure: sessions=%d refresh_tokens=%d", sessions, refreshTokens)
	}
}

func insertAccountUserForOperator(ctx context.Context, st *store.Store, id, email, status string) error {
	hash, err := security.DefaultPasswordHasher().Hash("account-password")
	if err != nil {
		return err
	}
	_, err = st.Pool.Exec(ctx, `
		INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ($1, $2, $2, $3, $4)
	`, id, email, hash, status)
	return err
}

func newOperatorStore(t *testing.T) *store.Store {
	t.Helper()
	database, err := operatorDB.Clone(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	st, err := store.Open(context.Background(), database.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	return st
}

func insertOperator(t *testing.T, st *store.Store, userID, email, capabilities string) {
	t.Helper()
	hash, err := security.DefaultPasswordHasher().Hash("operator-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(context.Background(), `
		INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ($1, $2, $2, $3, 'active')
	`, userID, email+"@example.test", hash); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(context.Background(), `INSERT INTO operators (user_id, capabilities) VALUES ($1, $2::jsonb)`, userID, capabilities); err != nil {
		t.Fatal(err)
	}
}

func insertOperatorSession(t *testing.T, st *store.Store, userID string, key []byte, digest *[32]byte) string {
	t.Helper()
	raw := "ply_ops_" + base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
	now := time.Now().UTC()
	stepOperation := ""
	stepDigest := []byte(nil)
	if digest != nil {
		stepOperation = "ops.operators.update"
		stepDigest = digest[:]
	}
	sessionID := string(ids.New[ids.OperatorSessionID]("ops"))
	if _, err := st.Pool.Exec(context.Background(), `
		INSERT INTO operator_sessions (id, user_id, token_hash, expires_at, idle_expires_at, access_expires_at, assurance_level, step_up_operation, step_up_digest, step_up_expires_at)
		VALUES ($1, $2, $3, $4::timestamptz, $5::timestamptz, $6::timestamptz, 2, NULLIF($7, ''), $8, CASE WHEN $7 = '' THEN NULL ELSE $4::timestamptz END)
	`, sessionID, userID, hashWithKey(raw, key), now.Add(8*time.Hour), now.Add(30*time.Minute), now.Add(10*time.Minute), stepOperation, stepDigest); err != nil {
		t.Fatal(err)
	}
	return raw
}

func assertDurationNear(t *testing.T, got, want time.Duration) {
	t.Helper()
	if diff := got - want; diff < -2*time.Second || diff > 2*time.Second {
		t.Fatalf("duration = %s, want %s", got, want)
	}
}

func assertOperatorError(t *testing.T, err error, want string) {
	t.Helper()
	var public *apierr.Error
	if !errors.As(err, &public) || public.Code != want {
		t.Fatalf("error = %v, want %s", err, want)
	}
}
