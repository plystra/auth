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
