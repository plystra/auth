package factor

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
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/store"
	"github.com/plystra/auth/internal/testdb"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

var factorDB *testdb.Harness

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var err error
	factorDB, err = testdb.Start(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	if err := factorDB.Close(context.Background()); err != nil && code == 0 {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	os.Exit(code)
}

func TestTOTPEncryptsSecretAndConsumesEachTimeStepOnce(t *testing.T) {
	ctx := context.Background()
	st := newFactorStore(t)
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ('usr_factor_totp', 'factor-totp@example.test', 'factor-totp@example.test', 'test-password-hash', 'active')
	`); err != nil {
		t.Fatal(err)
	}
	factors := &Service{Store: st, DataKey: secretKey()}
	enrollment, err := factors.BeginTOTP(ctx, "usr_factor_totp", "factor-totp@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if enrollment.FactorID == "" || enrollment.URI == "" || enrollment.Secret.Value() == "" {
		t.Fatalf("incomplete TOTP enrollment: %+v", enrollment)
	}
	if got := fmt.Sprint(enrollment.Secret); got != "[REDACTED]" {
		t.Fatalf("TOTP secret formatting = %q, want redaction", got)
	}
	var ciphertext []byte
	if err := st.Pool.QueryRow(ctx, `SELECT secret_ciphertext FROM factors WHERE id = $1`, enrollment.FactorID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if len(ciphertext) <= len(enrollment.Secret.Value()) || bytes.Equal(ciphertext, []byte(enrollment.Secret.Value())) {
		t.Fatal("TOTP secret was stored as plaintext")
	}

	fixed := time.Unix(1_700_000_015, 0).UTC()
	previousCode, err := totp.GenerateCodeCustom(enrollment.Secret.Value(), fixed.Add(-30*time.Second), totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyAt(ctx, st, factors, "usr_factor_totp", enrollment.FactorID, previousCode, fixed); err != nil {
		t.Fatalf("previous-step code was not accepted within the documented window: %v", err)
	}
	if err := verifyAt(ctx, st, factors, "usr_factor_totp", enrollment.FactorID, previousCode, fixed); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("replayed previous-step code error = %v, want ErrInvalidCode", err)
	}
	currentCode, err := totp.GenerateCodeCustom(enrollment.Secret.Value(), fixed, totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyAt(ctx, st, factors, "usr_factor_totp", enrollment.FactorID, currentCode, fixed); err != nil {
		t.Fatalf("current-step code was not accepted: %v", err)
	}
	if err := verifyAt(ctx, st, factors, "usr_factor_totp", enrollment.FactorID, currentCode, fixed); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("replayed current-step code error = %v, want ErrInvalidCode", err)
	}
}

func TestTOTPConcurrentVerificationConsumesTheTimeStepOnce(t *testing.T) {
	ctx := context.Background()
	st := newFactorStore(t)
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ('usr_factor_concurrent', 'factor-concurrent@example.test', 'factor-concurrent@example.test', 'test-password-hash', 'active')
	`); err != nil {
		t.Fatal(err)
	}
	factors := &Service{Store: st, DataKey: secretKey()}
	enrollment, err := factors.BeginTOTP(ctx, "usr_factor_concurrent", "factor-concurrent@example.test")
	if err != nil {
		t.Fatal(err)
	}
	fixed := time.Unix(1_700_000_045, 0).UTC()
	code, err := totp.GenerateCodeCustom(enrollment.Secret.Value(), fixed, totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- verifyAt(ctx, st, factors, "usr_factor_concurrent", enrollment.FactorID, code, fixed)
		}()
	}
	wg.Wait()
	close(results)
	var successes, rejected int
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrInvalidCode) {
			rejected++
		} else {
			t.Fatalf("concurrent TOTP verification error = %v", err)
		}
	}
	if successes != 1 || rejected != 1 {
		t.Fatalf("concurrent TOTP verification: successes=%d rejected=%d", successes, rejected)
	}
}

func TestTOTPInvalidAttemptsAreRateLimitedWithoutStoringIdentity(t *testing.T) {
	ctx := context.Background()
	st := newFactorStore(t)
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ('usr_factor_rate', 'factor-rate@example.test', 'factor-rate@example.test', 'test-password-hash', 'active')
	`); err != nil {
		t.Fatal(err)
	}
	factors := &Service{Store: st, DataKey: secretKey(), Limiter: &store.RateLimiter{Store: st}}
	enrollment, err := factors.BeginTOTP(ctx, "usr_factor_rate", "factor-rate@example.test")
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= 5; attempt++ {
		err := factors.VerifyTOTP(ctx, "usr_factor_rate", enrollment.FactorID, "abcdef")
		if !errors.Is(err, ErrInvalidCode) {
			t.Fatalf("invalid TOTP attempt %d error = %v, want ErrInvalidCode", attempt, err)
		}
	}
	err = factors.VerifyTOTP(ctx, "usr_factor_rate", enrollment.FactorID, "abcdef")
	var rateErr *apierr.Error
	if !errors.As(err, &rateErr) || rateErr.Code != "rate_limited" {
		t.Fatalf("sixth invalid TOTP attempt error = %v, want rate_limited", err)
	}
	var bucketKey string
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT bucket_key, count FROM rate_limit_buckets`).Scan(&bucketKey, &count); err != nil {
		t.Fatal(err)
	}
	if count != 6 || strings.Contains(bucketKey, "usr_factor_rate") || strings.Contains(bucketKey, enrollment.FactorID) || len(bucketKey) != 43 {
		t.Fatalf("TOTP failure bucket leaked identity or has wrong count/key: key=%q count=%d", bucketKey, count)
	}
}

func TestTOTPFailureLimitSurvivesIdempotentRequestRollback(t *testing.T) {
	ctx := context.Background()
	st := newFactorStore(t)
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ('usr_factor_idempotent', 'factor-idempotent@example.test', 'factor-idempotent@example.test', 'test-password-hash', 'active')
	`); err != nil {
		t.Fatal(err)
	}
	factors := &Service{Store: st, DataKey: secretKey(), Limiter: &store.RateLimiter{Store: st}}
	enrollment, err := factors.BeginTOTP(ctx, "usr_factor_idempotent", "factor-idempotent@example.test")
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= 6; attempt++ {
		request, err := st.BeginIdempotency(ctx)
		if err != nil {
			t.Fatal(err)
		}
		requestCtx := request.Context(ctx)
		err = st.InTx(requestCtx, func(q *db.Queries) error {
			return factors.VerifyTOTPTxRateLimited(requestCtx, q, "usr_factor_idempotent", enrollment.FactorID, "abcdef", time.Now().UTC())
		})
		if rollbackErr := request.Rollback(ctx); rollbackErr != nil {
			t.Fatal(rollbackErr)
		}
		if attempt <= 5 && !errors.Is(err, ErrInvalidCode) {
			t.Fatalf("attempt %d error = %v, want ErrInvalidCode", attempt, err)
		}
		if attempt == 6 {
			var public *apierr.Error
			if !errors.As(err, &public) || public.Code != "rate_limited" {
				t.Fatalf("sixth attempt error = %v, want rate_limited", err)
			}
		}
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count FROM rate_limit_buckets`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 6 {
		t.Fatalf("persisted failure count = %d, want 6", count)
	}
}

func TestBackupCodesAreSingleUseAndRegenerationRevokesOldCodes(t *testing.T) {
	ctx := context.Background()
	st := newFactorStore(t)
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ('usr_factor_backup', 'factor-backup@example.test', 'factor-backup@example.test', 'test-password-hash', 'active')
	`); err != nil {
		t.Fatal(err)
	}
	factors := &Service{Store: st, DataKey: secretKey()}
	oldCodes, err := factors.GenerateBackupCodesForUser(ctx, "usr_factor_backup", 6)
	if err != nil {
		t.Fatal(err)
	}
	if len(oldCodes) != 6 {
		t.Fatalf("generated %d backup codes, want 6", len(oldCodes))
	}
	var stored, plaintextCiphertexts, hashes int
	if err := st.Pool.QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (WHERE secret_ciphertext IS NOT NULL), count(*) FILTER (WHERE secret_hash IS NOT NULL)
		FROM factors WHERE user_id = 'usr_factor_backup' AND kind = 'backup_code'
	`).Scan(&stored, &plaintextCiphertexts, &hashes); err != nil {
		t.Fatal(err)
	}
	if stored != 6 || plaintextCiphertexts != 0 || hashes != 6 {
		t.Fatalf("backup code storage = stored %d plaintext_ciphertexts %d hashes %d", stored, plaintextCiphertexts, hashes)
	}
	if err := factors.ConsumeBackupCode(ctx, "usr_factor_backup", oldCodes[0]); err != nil {
		t.Fatalf("first backup code use failed: %v", err)
	}
	if err := factors.ConsumeBackupCode(ctx, "usr_factor_backup", oldCodes[0]); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("replayed backup code error = %v, want ErrInvalidCode", err)
	}

	newCodes, err := factors.GenerateBackupCodesForUser(ctx, "usr_factor_backup", 5)
	if err != nil {
		t.Fatal(err)
	}
	if err := factors.ConsumeBackupCode(ctx, "usr_factor_backup", oldCodes[1]); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("replaced backup code error = %v, want ErrInvalidCode", err)
	}
	if err := factors.ConsumeBackupCode(ctx, "usr_factor_backup", newCodes[0]); err != nil {
		t.Fatalf("new backup code use failed: %v", err)
	}
	concurrentCodes, err := factors.GenerateBackupCodesForUser(ctx, "usr_factor_backup", 5)
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	for range 2 {
		go func() { results <- factors.ConsumeBackupCode(ctx, "usr_factor_backup", concurrentCodes[0]) }()
	}
	var successes, rejected int
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrInvalidCode):
			rejected++
		default:
			t.Fatalf("concurrent backup code use returned unexpected error: %v", err)
		}
	}
	if successes != 1 || rejected != 1 {
		t.Fatalf("concurrent backup code use: successes=%d rejected=%d, want one each", successes, rejected)
	}
	var active int
	if err := st.Pool.QueryRow(ctx, `
		SELECT count(*) FROM factors
		WHERE user_id = 'usr_factor_backup' AND kind = 'backup_code' AND last_used_at IS NULL
	`).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 4 {
		t.Fatalf("active regenerated backup codes = %d, want 4", active)
	}
}

func verifyAt(ctx context.Context, st *store.Store, factors *Service, userID, factorID, code string, now time.Time) error {
	return st.InTx(ctx, func(q *db.Queries) error {
		return factors.VerifyTOTPTx(ctx, q, userID, factorID, code, now)
	})
}

func newFactorStore(t *testing.T) *store.Store {
	t.Helper()
	database, err := factorDB.Clone(context.Background())
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

func secretKey() secret.String {
	return secret.New(strings.Repeat("d", 32))
}
