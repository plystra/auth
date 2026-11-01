package session

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/factor"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/stepup"
	"github.com/plystra/auth/internal/store"
)

// StepUpRequirement is attached to a request context by the interaction plane
// after it has authenticated the request. The business transaction consumes
// the matching, single-use proof before applying its mutation.
type StepUpRequirement = stepup.Requirement

func WithStepUpRequirement(ctx context.Context, requirement StepUpRequirement) context.Context {
	return stepup.WithRequirement(ctx, requirement)
}

func StepUpRequirementFromContext(ctx context.Context) (StepUpRequirement, bool) {
	return stepup.RequirementFromContext(ctx)
}

// StepUp re-authenticates a user with TOTP and binds the result to the
// current access-token session, operation, and canonical request digest.
func (s *Service) StepUp(ctx context.Context, raw, code, operation string, digest []byte) error {
	operation = strings.TrimSpace(operation)
	if operation == "" || len(digest) != sha256.Size {
		return apierr.New("VALIDATION_FAILED", "operation and a canonical request digest are required")
	}
	if s == nil || s.Store == nil || s.Signer == nil || s.Factors == nil {
		return apierr.New("UNAVAILABLE", "step-up authentication is unavailable")
	}
	claims, active, err := s.Introspect(ctx, raw, security.DefaultApplicationAudience)
	if err != nil {
		return err
	}
	if !active {
		return apierr.New("UNAUTHENTICATED", "the access token is invalid")
	}
	if claims.Type != "user" {
		return apierr.New("USER_ACCOUNT_REQUIRED", "step-up requires a user account")
	}
	if claims.SessionID == "" {
		return apierr.New("UNAUTHENTICATED", "the access token has no session")
	}
	return s.Store.InTx(ctx, func(q *db.Queries) error {
		current, err := q.LockSessionForStepUp(ctx, db.LockSessionForStepUpParams{ID: claims.SessionID})
		if errors.Is(err, pgx.ErrNoRows) || err == nil && (current.UserID != claims.Subject || current.RevokedAt.Valid || !current.ExpiresAt.Time.After(time.Now().UTC())) {
			return apierr.New("UNAUTHENTICATED", "the access token is invalid")
		}
		if err != nil {
			return err
		}
		if err := s.Factors.VerifyTOTPTxRateLimited(ctx, q, current.UserID, "", code, time.Now().UTC()); err != nil {
			if errors.Is(err, factor.ErrInvalidCode) {
				return apierr.New("UNAUTHENTICATED", "the one-time code is invalid")
			}
			return err
		}
		_, err = q.SetSessionStepUp(ctx, db.SetSessionStepUpParams{
			ID: claims.SessionID, Operation: pgtype.Text{String: operation, Valid: true}, Digest: append([]byte(nil), digest...), Method: pgtype.Text{String: "totp", Valid: true},
		})
		if err != nil {
			return err
		}
		return audit.Write(ctx, q, "user", current.UserID, "auth.session.step_up", claims.SessionID, "success")
	})
}

// StepUpFirstTOTP permits password reauthentication only for first-factor
// enrollment. A persistent method marker prevents the proof from surviving
// another session's successful TOTP enrollment.
func (s *Service) StepUpFirstTOTP(ctx context.Context, raw string, password secret.String, digest []byte) error {
	if len(digest) != sha256.Size || password.Value() == "" {
		return apierr.New("VALIDATION_FAILED", "a password and canonical request digest are required")
	}
	if s == nil || s.Store == nil || s.Signer == nil {
		return apierr.New("UNAVAILABLE", "step-up authentication is unavailable")
	}
	claims, active, err := s.Introspect(ctx, raw, security.DefaultApplicationAudience)
	if err != nil {
		return err
	}
	if !active || claims.SessionID == "" {
		return apierr.New("UNAUTHENTICATED", "the access token is invalid")
	}
	if claims.Type != "user" {
		return apierr.New("USER_ACCOUNT_REQUIRED", "step-up requires a user account")
	}
	key := sha256.Sum256([]byte("plystra-auth-first-totp-step-up:" + claims.Subject))
	allowed, err := (store.RateLimiter{Store: s.Store}).Allow(
		store.WithoutRequestTransaction(ctx), "stepup:"+base64.RawURLEncoding.EncodeToString(key[:]), 5, 5*time.Minute,
	)
	if err != nil {
		return err
	}
	if !allowed {
		return apierr.New("rate_limited", "too many password verification attempts")
	}
	return s.Store.InTx(ctx, func(q *db.Queries) error {
		user, err := q.LockUserForStatus(ctx, db.LockUserForStatusParams{ID: claims.Subject})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("UNAUTHENTICATED", "the access token is invalid")
		}
		if err != nil {
			return err
		}
		if user.Status != "active" || user.DisabledAt.Valid {
			return apierr.New("UNAUTHENTICATED", "the access token is invalid")
		}
		count, err := q.CountTOTPFactors(ctx, db.CountTOTPFactorsParams{UserID: user.ID})
		if err != nil {
			return err
		}
		if count != 0 {
			return apierr.New("MFA_REQUIRED", "verify an existing authenticator to change factors")
		}
		if len(password.Value()) > security.MaxPasswordBytes || !security.DefaultPasswordHasher().Verify(password.Value(), user.PasswordHash) {
			return apierr.New("UNAUTHENTICATED", "the account credentials are invalid")
		}
		current, err := q.LockSessionForStepUp(ctx, db.LockSessionForStepUpParams{ID: claims.SessionID})
		if errors.Is(err, pgx.ErrNoRows) || err == nil && (current.UserID != user.ID || current.RevokedAt.Valid || !current.ExpiresAt.Time.After(time.Now().UTC())) {
			return apierr.New("UNAUTHENTICATED", "the access token is invalid")
		}
		if err != nil {
			return err
		}
		if _, err := q.SetSessionStepUp(ctx, db.SetSessionStepUpParams{
			ID: claims.SessionID, Operation: pgtype.Text{String: "me.factors.create", Valid: true},
			Digest: append([]byte(nil), digest...), Method: pgtype.Text{String: "password", Valid: true},
		}); err != nil {
			return err
		}
		return audit.Write(ctx, q, "user", user.ID, "auth.session.step_up", claims.SessionID, "success")
	})
}

// ConsumeStepUpTx consumes the proof attached to ctx. It is intentionally a
// no-op when no proof was requested so internal service callers and Agent
// flows do not inherit a human-only requirement.
func (s *Service) ConsumeStepUpTx(ctx context.Context, q *db.Queries) error {
	requirement, ok := stepup.RequirementFromContext(ctx)
	if !ok {
		return nil
	}
	if s == nil {
		return apierr.New("UNAVAILABLE", "step-up authentication is unavailable")
	}
	if strings.TrimSpace(requirement.SessionID) == "" || strings.TrimSpace(requirement.Operation) == "" || len(requirement.Digest) != sha256.Size {
		return apierr.New("STEP_UP_REQUIRED", "complete step-up for this operation and request")
	}
	_, err := q.ConsumeSessionStepUp(ctx, db.ConsumeSessionStepUpParams{
		ID: requirement.SessionID, Operation: pgtype.Text{String: requirement.Operation, Valid: true}, Digest: requirement.Digest,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return apierr.New("STEP_UP_REQUIRED", "complete step-up for this operation and request")
	}
	return err
}
