package operator

import (
	"context"
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
