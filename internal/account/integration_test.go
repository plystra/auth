package account

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
