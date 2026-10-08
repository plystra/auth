package session

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/factor"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/stepup"
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
			ID: claims.SessionID, Operation: pgtype.Text{String: operation, Valid: true}, Digest: append([]byte(nil), digest...),
		})
		return err
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
