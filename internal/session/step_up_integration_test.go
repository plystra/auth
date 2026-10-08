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

	wrong := WithStepUpRequirement(ctx, stepup.Requirement{SessionID: tokens.SessionID, Operation: "me.agents.rotate", Digest: digest})
	if err := st.InTx(wrong, func(q *db.Queries) error { return sessions.ConsumeStepUpTx(wrong, q) }); err == nil {
		t.Fatal("step-up proof was accepted for a different operation")
	}
}
