package account

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/space"
	"github.com/plystra/auth/internal/store"
	"github.com/plystra/auth/internal/testdb"
)

var accountDB *testdb.Harness

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var err error
	accountDB, err = testdb.Start(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	if err := accountDB.Close(context.Background()); err != nil && code == 0 {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	os.Exit(code)
}

func TestEmailNormalizationIsUniqueAndRegistrationDefaultsClosed(t *testing.T) {
	ctx := context.Background()
	st := newAccountStore(t)
	settings := &space.Service{Store: st}
	accounts := &Service{Store: st, Passwords: security.DefaultPasswordHasher(), Settings: settings}
	if _, err := accounts.Register(ctx, RegisterInput{Email: "closed@example.test", Password: "a sufficiently long password"}, nil, ""); err == nil {
		t.Fatal("registration was open by default")
	} else {
		assertAccountError(t, err, "forbidden")
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE instance_settings SET registration_mode = 'open'`); err != nil {
		t.Fatal(err)
	}
	if _, err := accounts.Register(ctx, RegisterInput{Email: "  Mixed.Case@Example.Test ", Password: "a sufficiently long password"}, nil, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := accounts.Register(ctx, RegisterInput{Email: "mixed.case@example.test", Password: "a sufficiently long password"}, nil, ""); err == nil {
		t.Fatal("registration accepted a duplicate normalized email")
	} else {
		assertAccountError(t, err, "conflict")
	}
}

func TestSetUserStatusRevokesSessionsAndRefreshTokensAtomically(t *testing.T) {
	ctx := context.Background()
	st := newAccountStore(t)
	if err := insertAccountUser(ctx, st, "usr_status_target", "status-target@example.test", "active"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO sessions (id, user_id, token_hash, expires_at)
		VALUES ('ses_status_target', 'usr_status_target', decode(repeat('11', 32), 'hex'), now() + interval '1 hour')
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO refresh_tokens (id, session_id, family_id, token_hash, expires_at)
		VALUES ('rft_status_target', 'ses_status_target', 'rtf_status_target', decode(repeat('22', 32), 'hex'), now() + interval '1 hour')
	`); err != nil {
		t.Fatal(err)
	}
	accounts := &Service{Store: st}
	if err := accounts.SetUserStatus(ctx, "operator", "usr_operator", "usr_status_target", "suspended"); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := st.Pool.QueryRow(ctx, `SELECT status FROM users WHERE id = 'usr_status_target'`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "suspended" {
		t.Fatalf("user status = %q, want suspended", status)
	}
	var sessions, refreshTokens int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE id = 'ses_status_target' AND revoked_at IS NULL`).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM refresh_tokens WHERE id = 'rft_status_target' AND revoked_at IS NULL`).Scan(&refreshTokens); err != nil {
		t.Fatal(err)
	}
	if sessions != 0 || refreshTokens != 0 {
		t.Fatalf("active credentials after suspension: sessions=%d refresh_tokens=%d", sessions, refreshTokens)
	}
	assertAuditAction(t, st, "user.status.update", "usr_operator")
}

func TestSetUserStatusAcceptsAllDocumentedStatesAndRejectsUnknownState(t *testing.T) {
	ctx := context.Background()
	st := newAccountStore(t)
	if err := insertAccountUser(ctx, st, "usr_status_states", "status-states@example.test", "active"); err != nil {
		t.Fatal(err)
	}
	accounts := &Service{Store: st}
	for _, status := range []string{"pending", "active", "suspended", "disabled"} {
		if err := accounts.SetUserStatus(ctx, "operator", "usr_operator", "usr_status_states", status); err != nil {
			t.Fatalf("SetUserStatus(%q): %v", status, err)
		}
	}
	if err := accounts.SetUserStatus(ctx, "operator", "usr_operator", "usr_status_states", "unknown"); err == nil {
		t.Fatal("unknown user status was accepted")
	} else {
		assertAccountError(t, err, "VALIDATION_FAILED")
	}
}

func TestSetUserStatusAuditFailureRollsBackStateAndCredentialRevocation(t *testing.T) {
	ctx := context.Background()
	st := newAccountStore(t)
	if err := insertAccountUser(ctx, st, "usr_status_rollback", "status-rollback@example.test", "active"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO sessions (id, user_id, token_hash, expires_at)
		VALUES ('ses_status_rollback', 'usr_status_rollback', decode(repeat('33', 32), 'hex'), now() + interval '1 hour')
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO refresh_tokens (id, session_id, family_id, token_hash, expires_at)
		VALUES ('rft_status_rollback', 'ses_status_rollback', 'rtf_status_rollback', decode(repeat('44', 32), 'hex'), now() + interval '1 hour')
	`); err != nil {
		t.Fatal(err)
	}
	rejectAuditInserts(t, st, "injected user status audit failure")
	accounts := &Service{Store: st}
	if err := accounts.SetUserStatus(ctx, "operator", "usr_operator", "usr_status_rollback", "disabled"); err == nil {
		t.Fatal("status change succeeded despite audit failure")
	}
	var status string
	if err := st.Pool.QueryRow(ctx, `SELECT status FROM users WHERE id = 'usr_status_rollback'`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "active" {
		t.Fatalf("user status after audit failure = %q, want active", status)
	}
	var activeSessions, activeRefreshTokens int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE id = 'ses_status_rollback' AND revoked_at IS NULL`).Scan(&activeSessions); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM refresh_tokens WHERE id = 'rft_status_rollback' AND revoked_at IS NULL`).Scan(&activeRefreshTokens); err != nil {
		t.Fatal(err)
	}
	if activeSessions != 1 || activeRefreshTokens != 1 {
		t.Fatalf("credentials after audit failure: sessions=%d refresh_tokens=%d", activeSessions, activeRefreshTokens)
	}
}

func TestConcurrentRegistrationSameEmailHasSingleSuccess(t *testing.T) {
	ctx := context.Background()
	st := newAccountStore(t)
	if _, err := st.Pool.Exec(ctx, `UPDATE instance_settings SET registration_mode = 'open'`); err != nil {
		t.Fatal(err)
	}
	settings := &space.Service{Store: st}
	accounts := &Service{Store: st, Passwords: security.DefaultPasswordHasher(), Settings: settings}

	const attempts = 8
	start := make(chan struct{})
	results := make(chan error, attempts)
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := accounts.Register(ctx, RegisterInput{
				Email:    "Concurrent.User@Example.Test",
				Password: "a sufficiently long password",
			}, nil, "")
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	successes := 0
	conflicts := 0
	for err := range results {
		if err == nil {
			successes++
			continue
		}
		assertAccountError(t, err, "conflict")
		conflicts++
	}
	if successes != 1 || conflicts != attempts-1 {
		t.Fatalf("concurrent registrations: successes=%d conflicts=%d, want one success and %d conflicts", successes, conflicts, attempts-1)
	}
}

func TestRegistrationRollsBackUserAndDefaultMembershipWhenAuditFails(t *testing.T) {
	ctx := context.Background()
	st := newAccountStore(t)
	if _, err := st.Pool.Exec(ctx, `UPDATE instance_settings SET registration_mode = 'open', require_email_verification = false`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		CREATE FUNCTION reject_registration_audit_insert() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'registration audit insert rejected by test'; END;
		$$;
		CREATE TRIGGER test_reject_registration_audit BEFORE INSERT ON audit_logs
		FOR EACH ROW EXECUTE FUNCTION reject_registration_audit_insert();
	`); err != nil {
		t.Fatal(err)
	}
	authz := &authorization.Service{Store: st}
	accounts := &Service{Store: st, Passwords: security.DefaultPasswordHasher(), Settings: &space.Service{Store: st}, Authorization: authz}
	if _, err := accounts.Register(ctx, RegisterInput{Email: "rollback@example.test", Password: "a sufficiently long password"}, nil, ""); err == nil {
		t.Fatal("registration succeeded despite audit failure")
	}
	var users, members int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE email_normalized = 'rollback@example.test'`).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM members WHERE name = 'rollback@example.test'`).Scan(&members); err != nil {
		t.Fatal(err)
	}
	if users != 0 || members != 0 {
		t.Fatalf("registration left partial state: users=%d members=%d", users, members)
	}
}

func TestRegistrationCreatesDefaultMemberBindingAndGrant(t *testing.T) {
	ctx := context.Background()
	st := newAccountStore(t)
	if _, err := st.Pool.Exec(ctx, `UPDATE instance_settings SET registration_mode = 'open'`); err != nil {
		t.Fatal(err)
	}
	authz := &authorization.Service{Store: st}
	accounts := &Service{Store: st, Passwords: security.DefaultPasswordHasher(), Settings: &space.Service{Store: st}, Authorization: authz}
	result, err := accounts.Register(ctx, RegisterInput{Email: "joined@example.test", Password: "a sufficiently long password"}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if result.User.Status != "pending" {
		t.Fatalf("registered user status = %q, want pending", result.User.Status)
	}
	var memberID string
	if err := st.Pool.QueryRow(ctx, `
		SELECT m.id FROM members m JOIN user_members um ON um.member_id = m.id
		WHERE um.user_id = $1 AND m.space_id = $2 AND m.type = 'human' AND um.status = 'active'
	`, result.User.ID, DefaultSpaceID).Scan(&memberID); err != nil {
		t.Fatal(err)
	}
	var grants, audits int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM authorization_grants WHERE grantee_member_id = $1 AND revoked_at IS NULL`, memberID).Scan(&grants); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action IN ('auth.register', 'member.default_bind') AND actor_id IN ($1, 'system')`, result.User.ID).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if grants != 1 || audits != 2 {
		t.Fatalf("registration state: grants=%d audits=%d, want one grant and two audit entries", grants, audits)
	}
}

func TestLoginRehashesLegacyPasswordAndRejectsOverlongInput(t *testing.T) {
	ctx := context.Background()
	st := newAccountStore(t)
	legacy := security.PasswordHasher{Time: 1, Memory: 8 * 1024, Threads: 1, KeyLen: 32, SaltLen: 16}
	const password = "a sufficiently long password"
	legacyHash, err := legacy.Hash(password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ($1, $2, $2, $3, 'active')
	`, "usr_rehash_user", "rehash@example.test", legacyHash); err != nil {
		t.Fatal(err)
	}
	signer, err := security.GenerateSigner("https://auth.test")
	if err != nil {
		t.Fatal(err)
	}
	sessions := &session.Service{
		Store:    st,
		Signer:   signer,
		HMACKeys: [][]byte{[]byte(strings.Repeat("h", 32))},
		Settings: func(context.Context) (session.Settings, error) {
			return session.Settings{AccessTTL: time.Minute, RefreshTTL: time.Hour, RefreshIdleTTL: 30 * time.Minute}, nil
		},
	}
	accounts := &Service{Store: st, Passwords: security.DefaultPasswordHasher(), Sessions: sessions, Settings: &space.Service{Store: st}}
	result, err := accounts.Login(ctx, LoginInput{Email: "REHASH@example.test", Password: password})
	if err != nil {
		t.Fatal(err)
	}
	if result.Tokens == nil || result.Tokens.AccessToken == "" {
		t.Fatal("successful login did not issue an access token")
	}
	var upgraded string
	if err := st.Pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE id = $1`, "usr_rehash_user").Scan(&upgraded); err != nil {
		t.Fatal(err)
	}
	if upgraded == legacyHash || accounts.Passwords.NeedsRehash(upgraded) || !accounts.Passwords.Verify(password, upgraded) {
		t.Fatal("legacy password hash was not upgraded to the current parameters")
	}
	var audits int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE actor_id = $1 AND action = 'auth.password.rehash'`, "usr_rehash_user").Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 1 {
		t.Fatalf("password rehash audit count = %d, want 1", audits)
	}
	var sessionsBefore int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE user_id = $1`, "usr_rehash_user").Scan(&sessionsBefore); err != nil {
		t.Fatal(err)
	}
	if _, err := accounts.Login(ctx, LoginInput{Email: "rehash@example.test", Password: strings.Repeat("x", security.MaxPasswordBytes+1)}); err == nil {
		t.Fatal("overlong login password was accepted")
	} else {
		assertAccountError(t, err, "invalid_credentials")
	}
	var sessionsAfter int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE user_id = $1`, "usr_rehash_user").Scan(&sessionsAfter); err != nil {
		t.Fatal(err)
	}
	if sessionsAfter != sessionsBefore {
		t.Fatalf("overlong login created a session: before=%d after=%d", sessionsBefore, sessionsAfter)
	}
}

func TestLoginAttemptsAreRateLimitedByIPAccountAndPair(t *testing.T) {
	ctx := context.Background()
	st := newAccountStore(t)
	accounts := &Service{Store: st, Passwords: security.DefaultPasswordHasher(), Settings: &space.Service{Store: st}, Limiter: &store.RateLimiter{Store: st}}

	for i := 0; i < 5; i++ {
		if _, err := accounts.Login(ctx, LoginInput{Email: "pair-limit@example.test", Password: "wrong", IP: net.ParseIP("192.0.2.1")}); err == nil {
			t.Fatal("login unexpectedly succeeded")
		} else {
			assertAccountError(t, err, "invalid_credentials")
		}
	}
	if _, err := accounts.Login(ctx, LoginInput{Email: "pair-limit@example.test", Password: "wrong", IP: net.ParseIP("192.0.2.1")}); err == nil {
		t.Fatal("login pair limit was not enforced")
	} else {
		assertAccountError(t, err, "rate_limited")
	}

	for i := 0; i < 10; i++ {
		ip := net.ParseIP(fmt.Sprintf("198.51.100.%d", i+1))
		if _, err := accounts.Login(ctx, LoginInput{Email: "account-limit@example.test", Password: "wrong", IP: ip}); err == nil {
			t.Fatal("login unexpectedly succeeded")
		} else {
			assertAccountError(t, err, "invalid_credentials")
		}
	}
	if _, err := accounts.Login(ctx, LoginInput{Email: "account-limit@example.test", Password: "wrong", IP: net.ParseIP("198.51.100.11")}); err == nil {
		t.Fatal("login account limit was not enforced")
	} else {
		assertAccountError(t, err, "rate_limited")
	}

	for i := 0; i < 30; i++ {
		if _, err := accounts.Login(ctx, LoginInput{Email: fmt.Sprintf("ip-limit-%d@example.test", i), Password: "wrong", IP: net.ParseIP("203.0.113.1")}); err == nil {
			t.Fatal("login unexpectedly succeeded")
		} else {
			assertAccountError(t, err, "invalid_credentials")
		}
	}
	if _, err := accounts.Login(ctx, LoginInput{Email: "ip-limit-final@example.test", Password: "wrong", IP: net.ParseIP("203.0.113.1")}); err == nil {
		t.Fatal("login IP limit was not enforced")
	} else {
		assertAccountError(t, err, "rate_limited")
	}
}

func TestPasswordResetAndVerificationAttemptsAreRateLimitedWithoutEnumeration(t *testing.T) {
	ctx := context.Background()
	st := newAccountStore(t)
	accounts := &Service{Store: st, Passwords: security.DefaultPasswordHasher(), Settings: &space.Service{Store: st}, Limiter: &store.RateLimiter{Store: st}}

	for i := 0; i < 5; i++ {
		if token, err := accounts.RequestPasswordReset(ctx, "unknown-reset@example.test", net.ParseIP("198.51.100.10")); err != nil || token != "" {
			t.Fatalf("unknown reset request = token %q, error %v; want empty token and no error", token, err)
		}
	}
	if _, err := accounts.RequestPasswordReset(ctx, "unknown-reset@example.test", net.ParseIP("198.51.100.10")); err == nil {
		t.Fatal("password reset request IP/account/pair limit was not enforced")
	} else {
		assertAccountError(t, err, "rate_limited")
	}

	for i := 0; i < 5; i++ {
		if err := accounts.VerifyEmail(ctx, "invalid-email-token", net.ParseIP("198.51.100.11")); err == nil {
			t.Fatal("invalid email token was accepted")
		} else {
			assertAccountError(t, err, "invalid_grant")
		}
	}
	if err := accounts.VerifyEmail(ctx, "invalid-email-token", net.ParseIP("198.51.100.11")); err == nil {
		t.Fatal("email verification limit was not enforced")
	} else {
		assertAccountError(t, err, "rate_limited")
	}

	for i := 0; i < 5; i++ {
		if err := accounts.ResetPassword(ctx, "invalid-reset-token", "a newly secure password", net.ParseIP("198.51.100.12")); err == nil {
			t.Fatal("invalid reset token was accepted")
		} else {
			assertAccountError(t, err, "invalid_grant")
		}
	}
	if err := accounts.ResetPassword(ctx, "invalid-reset-token", "a newly secure password", net.ParseIP("198.51.100.12")); err == nil {
		t.Fatal("password reset confirmation limit was not enforced")
	} else {
		assertAccountError(t, err, "rate_limited")
	}
}

func TestLoginRejectsPasswordResetRequiredAccounts(t *testing.T) {
	ctx := context.Background()
	st := newAccountStore(t)
	passwords := security.DefaultPasswordHasher()
	hash, err := passwords.Hash("a sufficiently long password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO users (id, email, email_normalized, password_hash, status, password_reset_required_at)
		VALUES ('usr_reset_required', 'reset-required@example.test', 'reset-required@example.test', $1, 'active', now())
	`, hash); err != nil {
		t.Fatal(err)
	}
	accounts := &Service{Store: st, Passwords: passwords, Settings: &space.Service{Store: st}}
	if _, err := accounts.Login(ctx, LoginInput{Email: "reset-required@example.test", Password: "a sufficiently long password"}); err == nil {
		t.Fatal("login succeeded while password reset was required")
	} else {
		assertAccountError(t, err, "PASSWORD_RESET_REQUIRED")
	}
}

func TestPasswordResetClearsRequiredFlag(t *testing.T) {
	ctx := context.Background()
	st := newAccountStore(t)
	if err := insertAccountUser(ctx, st, "usr_reset_clear", "reset-clear@example.test", "active"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE users SET password_reset_required_at = now() WHERE id = 'usr_reset_clear'`); err != nil {
		t.Fatal(err)
	}
	accounts := &Service{Store: st, Passwords: security.DefaultPasswordHasher(), Settings: &space.Service{Store: st}}
	token, err := accounts.RequestPasswordReset(ctx, "reset-clear@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := accounts.ResetPassword(ctx, token, "a newly secure password"); err != nil {
		t.Fatal(err)
	}
	var required bool
	if err := st.Pool.QueryRow(ctx, `SELECT password_reset_required_at IS NOT NULL FROM users WHERE id = 'usr_reset_clear'`).Scan(&required); err != nil {
		t.Fatal(err)
	}
	if required {
		t.Fatal("password reset required flag was not cleared")
	}
}

func TestVerificationAndResetTokensAreHashedSingleUseAndRevokeSessions(t *testing.T) {
	ctx := context.Background()
	st := newAccountStore(t)
	if err := insertAccountUser(ctx, st, "usr_token_user", "token-user@example.test", "pending"); err != nil {
		t.Fatal(err)
	}
	settings := &space.Service{Store: st}
	accounts := &Service{Store: st, Passwords: security.DefaultPasswordHasher(), Settings: settings}
	verification, err := accounts.CreateEmailVerification(ctx, "usr_token_user")
	if err != nil {
		t.Fatal(err)
	}
	var verificationHash []byte
	if err := st.Pool.QueryRow(ctx, `SELECT token_hash FROM email_verification_tokens WHERE user_id = $1`, "usr_token_user").Scan(&verificationHash); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(verificationHash, []byte(verification)) {
		t.Fatal("email verification token was stored in plaintext")
	}
	if err := accounts.VerifyEmail(ctx, verification); err != nil {
		t.Fatal(err)
	}
	assertAuditAction(t, st, "auth.email.verify", "usr_token_user")
	if err := accounts.VerifyEmail(ctx, verification); err == nil {
		t.Fatal("email verification token was reusable")
	}
	expiredVerification, err := accounts.CreateEmailVerification(ctx, "usr_token_user")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE email_verification_tokens SET expires_at = now() - interval '1 second' WHERE user_id = $1 AND consumed_at IS NULL`, "usr_token_user"); err != nil {
		t.Fatal(err)
	}
	if err := accounts.VerifyEmail(ctx, expiredVerification); err == nil {
		t.Fatal("expired email verification token was accepted")
	} else {
		assertAccountError(t, err, "invalid_grant")
	}

	if err := insertAccountUser(ctx, st, "usr_reset_user", "reset-user@example.test", "active"); err != nil {
		t.Fatal(err)
	}
	signer, err := security.GenerateSigner("https://auth.test")
	if err != nil {
		t.Fatal(err)
	}
	sessions := &session.Service{Store: st, Signer: signer, HMACKeys: [][]byte{[]byte(strings.Repeat("h", 32))}, Settings: func(context.Context) (session.Settings, error) {
		return session.Settings{AccessTTL: time.Minute, RefreshTTL: time.Hour, RefreshIdleTTL: 30 * time.Minute}, nil
	}}
	accounts.Sessions = sessions
	tokens, err := sessions.CreateForMember(ctx, "usr_reset_user", "", nil, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	reset, err := accounts.RequestPasswordReset(ctx, "RESET-USER@example.test")
	if err != nil {
		t.Fatal(err)
	}
	var resetHash []byte
	if err := st.Pool.QueryRow(ctx, `SELECT token_hash FROM password_reset_tokens WHERE user_id = $1`, "usr_reset_user").Scan(&resetHash); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(resetHash, []byte(reset)) {
		t.Fatal("password reset token was stored in plaintext")
	}
	if err := accounts.ResetPassword(ctx, reset, "a newly secure password"); err != nil {
		t.Fatal(err)
	}
	assertAuditAction(t, st, "auth.password.reset", "usr_reset_user")
	if err := accounts.ResetPassword(ctx, reset, "a newly secure password"); err == nil {
		t.Fatal("password reset token was reusable")
	}
	expiredReset, err := accounts.RequestPasswordReset(ctx, "reset-user@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE password_reset_tokens SET expires_at = now() - interval '1 second' WHERE user_id = $1 AND consumed_at IS NULL`, "usr_reset_user"); err != nil {
		t.Fatal(err)
	}
	if err := accounts.ResetPassword(ctx, expiredReset, "another secure password"); err == nil {
		t.Fatal("expired password reset token was accepted")
	} else {
		assertAccountError(t, err, "invalid_grant")
	}
	if _, active, err := sessions.Introspect(ctx, tokens.AccessToken, security.DefaultApplicationAudience); err != nil {
		t.Fatal(err)
	} else if active {
		t.Fatal("password reset did not revoke the existing session")
	}
}

func TestEmailVerificationRollsBackWhenAuditFails(t *testing.T) {
	ctx := context.Background()
	st := newAccountStore(t)
	if err := insertAccountUser(ctx, st, "usr_verify_rollback", "verify-rollback@example.test", "pending"); err != nil {
		t.Fatal(err)
	}
	accounts := &Service{Store: st, Passwords: security.DefaultPasswordHasher(), Settings: &space.Service{Store: st}}
	token, err := accounts.CreateEmailVerification(ctx, "usr_verify_rollback")
	if err != nil {
		t.Fatal(err)
	}
	rejectAuditInserts(t, st, "verification audit failure")
	if err := accounts.VerifyEmail(ctx, token); err == nil {
		t.Fatal("email verification succeeded despite audit failure")
	}
	var verified, consumed bool
	if err := st.Pool.QueryRow(ctx, `
		SELECT u.email_verified_at IS NOT NULL, t.consumed_at IS NOT NULL
		FROM users u JOIN email_verification_tokens t ON t.user_id = u.id
		WHERE u.id = $1
	`, "usr_verify_rollback").Scan(&verified, &consumed); err != nil {
		t.Fatal(err)
	}
	if verified || consumed {
		t.Fatalf("email verification state changed after audit failure: verified=%v consumed=%v", verified, consumed)
	}
}

func TestPasswordResetRollsBackWhenAuditFails(t *testing.T) {
	ctx := context.Background()
	st := newAccountStore(t)
	passwords := security.DefaultPasswordHasher()
	oldHash, err := passwords.Hash("the original secure password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ('usr_reset_rollback', 'reset-rollback@example.test', 'reset-rollback@example.test', $1, 'active')
	`, oldHash); err != nil {
		t.Fatal(err)
	}
	signer, err := security.GenerateSigner("https://auth.test")
	if err != nil {
		t.Fatal(err)
	}
	sessions := &session.Service{Store: st, Signer: signer, HMACKeys: [][]byte{[]byte(strings.Repeat("h", 32))}, Settings: func(context.Context) (session.Settings, error) {
		return session.Settings{AccessTTL: time.Minute, RefreshTTL: time.Hour, RefreshIdleTTL: 30 * time.Minute}, nil
	}}
	accounts := &Service{Store: st, Passwords: passwords, Sessions: sessions, Settings: &space.Service{Store: st}}
	issued, err := sessions.CreateForMember(ctx, "usr_reset_rollback", "", nil, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	token, err := accounts.RequestPasswordReset(ctx, "reset-rollback@example.test")
	if err != nil {
		t.Fatal(err)
	}
	rejectAuditInserts(t, st, "password reset audit failure")
	if err := accounts.ResetPassword(ctx, token, "the replacement secure password"); err == nil {
		t.Fatal("password reset succeeded despite audit failure")
	}
	var persistedHash string
	if err := st.Pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE id = $1`, "usr_reset_rollback").Scan(&persistedHash); err != nil {
		t.Fatal(err)
	}
	if persistedHash != oldHash {
		t.Fatal("password hash changed after audit failure")
	}
	var consumed, revoked bool
	if err := st.Pool.QueryRow(ctx, `
		SELECT t.consumed_at IS NOT NULL, s.revoked_at IS NOT NULL
		FROM password_reset_tokens t CROSS JOIN sessions s
		WHERE t.user_id = $1 AND s.user_id = $1
	`, "usr_reset_rollback").Scan(&consumed, &revoked); err != nil {
		t.Fatal(err)
	}
	if consumed || revoked {
		t.Fatalf("password reset state changed after audit failure: consumed=%v revoked=%v", consumed, revoked)
	}
	if _, active, err := sessions.Introspect(ctx, issued.AccessToken, security.DefaultApplicationAudience); err != nil {
		t.Fatal(err)
	} else if !active {
		t.Fatal("existing session was revoked after audit failure")
	}
}

func newAccountStore(t *testing.T) *store.Store {
	t.Helper()
	database, err := accountDB.Clone(context.Background())
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

func insertAccountUser(ctx context.Context, st *store.Store, id, email, status string) error {
	_, err := st.Pool.Exec(ctx, `
		INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ($1, $2, lower($2), 'test-password-hash', $3)
	`, id, email, status)
	return err
}

func assertAccountError(t *testing.T, err error, code string) {
	t.Helper()
	var public *apierr.Error
	if !errors.As(err, &public) || public.Code != code {
		t.Fatalf("error = %v, want code %q", err, code)
	}
}

func assertAuditAction(t *testing.T, st *store.Store, action, actorID string) {
	t.Helper()
	var count int
	if err := st.Pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_logs WHERE action = $1 AND actor_id = $2`, action, actorID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("audit action %q count = %d, want 1", action, count)
	}
}

func rejectAuditInserts(t *testing.T, st *store.Store, message string) {
	t.Helper()
	if _, err := st.Pool.Exec(context.Background(), fmt.Sprintf(`
		CREATE FUNCTION reject_account_audit_insert() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION '%s'; END;
		$$;
		CREATE TRIGGER test_reject_account_audit BEFORE INSERT ON audit_logs
		FOR EACH ROW EXECUTE FUNCTION reject_account_audit_insert();
	`, message)); err != nil {
		t.Fatal(err)
	}
}
