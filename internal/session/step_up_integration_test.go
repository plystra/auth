package session

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/factor"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/stepup"
	"github.com/plystra/auth/internal/store"
	"github.com/pquerna/otp/totp"
)

func TestPrincipalStepUpBindsOperationRequestAndRollsBackConsumption(t *testing.T) {
	ctx := context.Background()
	database, err := sessionDB.Clone(ctx)
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
		INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ('usr_step_up', 'step-up@example.test', 'step-up@example.test', 'test-password-hash', 'active')
	`); err != nil {
		t.Fatal(err)
	}
	signer, err := security.GenerateSigner("https://auth.test")
	if err != nil {
		t.Fatal(err)
	}
	factors := &factor.Service{Store: st, DataKey: secret.New(strings.Repeat("d", 32))}
	sessions := &Service{
		Store: st, Signer: signer, Factors: factors, HMACKeys: [][]byte{[]byte(strings.Repeat("h", 32))},
		Settings: func(context.Context) (Settings, error) {
			return Settings{AccessTTL: time.Minute, RefreshTTL: time.Hour, RefreshIdleTTL: 30 * time.Minute}, nil
		},
	}
	enrollment, err := factors.BeginTOTP(ctx, "usr_step_up", "step-up@example.test")
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := sessions.Create(ctx, "usr_step_up", nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	digest := []byte(strings.Repeat("x", 32))
	code, err := totp.GenerateCode(enrollment.Secret.Value(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := sessions.StepUp(ctx, tokens.AccessToken, code, "members.bindings.create", digest); err != nil {
		t.Fatalf("step-up = %v", err)
	}
	var assurance int16
	var audits int
	if err := st.Pool.QueryRow(ctx, `SELECT assurance_level FROM sessions WHERE id = $1`, tokens.SessionID).Scan(&assurance); err != nil {
		t.Fatal(err)
	}
	if assurance != 1 {
		t.Fatalf("session assurance = %d, step-up must not permanently elevate it", assurance)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'auth.session.step_up' AND resource_id = $1`, tokens.SessionID).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 1 {
		t.Fatalf("step-up audit count = %d, want 1", audits)
	}
	wrong := WithStepUpRequirement(ctx, stepup.Requirement{SessionID: tokens.SessionID, Operation: "me.agents.rotate", Digest: digest})
	if err := st.InTx(wrong, func(q *db.Queries) error { return sessions.ConsumeStepUpTx(wrong, q) }); err == nil {
		t.Fatal("step-up proof was accepted for a different operation")
	}
	wrongDigest := WithStepUpRequirement(ctx, stepup.Requirement{SessionID: tokens.SessionID, Operation: "members.bindings.create", Digest: []byte(strings.Repeat("y", 32))})
	if err := st.InTx(wrongDigest, func(q *db.Queries) error { return sessions.ConsumeStepUpTx(wrongDigest, q) }); err == nil {
		t.Fatal("step-up proof was accepted for a different request digest")
	}
	requirement := StepUpRequirement{SessionID: tokens.SessionID, Operation: "members.bindings.create", Digest: digest}
	rollbackCtx := WithStepUpRequirement(ctx, requirement)
	if err := st.InTx(rollbackCtx, func(q *db.Queries) error {
		if err := sessions.ConsumeStepUpTx(rollbackCtx, q); err != nil {
			return err
		}
		return errors.New("business mutation failed")
	}); err == nil || !strings.Contains(err.Error(), "business mutation failed") {
		t.Fatalf("rollback transaction error = %v", err)
	}
	if err := st.InTx(rollbackCtx, func(q *db.Queries) error {
		return sessions.ConsumeStepUpTx(rollbackCtx, q)
	}); err != nil {
		t.Fatalf("rolled-back step-up proof was lost: %v", err)
	}
	if err := st.InTx(rollbackCtx, func(q *db.Queries) error {
		return sessions.ConsumeStepUpTx(rollbackCtx, q)
	}); err == nil {
		t.Fatal("step-up proof was reusable")
	} else {
		var public *apierr.Error
		if !errors.As(err, &public) || public.Code != "STEP_UP_REQUIRED" {
			t.Fatalf("second consumption error = %v, want STEP_UP_REQUIRED", err)
		}
	}

}
