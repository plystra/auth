package account

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/security"
)

const (
	signInAttemptLifetime = 10 * time.Minute
	maxSignInFailures     = 5
)

type SignInChallenge struct {
	AttemptID string    `json:"attempt_id"`
	NextStep  string    `json:"next_step"`
	ExpiresAt time.Time `json:"expires_at"`
}

// BeginSignIn creates a short-lived server-side workflow. The response is the
// same for known and unknown accounts; account existence is never exposed by
// the challenge metadata.
func (s *Service) BeginSignIn(ctx context.Context, in LoginInput) (SignInChallenge, error) {
	email := strings.TrimSpace(strings.ToLower(in.Email))
	if !validEmail(email) {
		return SignInChallenge{}, apierr.New("invalid_request", "a valid email is required")
	}
	if err := s.allowLoginRateLimits(ctx, email, in.IP); err != nil {
		return SignInChallenge{}, err
	}

	var userID pgtype.Text
	row, err := s.Store.Queries().GetUserByEmail(ctx, db.GetUserByEmailParams{EmailNormalized: email})
	if err == nil {
		userID = pgtype.Text{String: row.ID, Valid: true}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return SignInChallenge{}, err
	}
	expiresAt := time.Now().UTC().Add(signInAttemptLifetime)
	attempt, err := s.Store.Queries().CreateSignInAttempt(ctx, db.CreateSignInAttemptParams{
		ID: string(ids.New[ids.SignInAttemptID]("sia")), UserID: userID,
		EmailNormalized: email, Ip: nullableText(rateIdentity(in.IP)), UserAgent: nullableText(in.UserAgent),
		ExpiresAt: pgtype.Timestamptz{Time: expiresAt, Valid: true},
	})
	if err != nil {
		return SignInChallenge{}, err
	}
	return SignInChallenge{AttemptID: attempt.ID, NextStep: "password", ExpiresAt: attempt.ExpiresAt.Time}, nil
}

// CompleteSignIn consumes a password step and issues a normal user session.
// The attempt row is locked while the password is checked, so concurrent
// submissions cannot both consume the same workflow.
func (s *Service) CompleteSignIn(ctx context.Context, attemptID, password string, ip net.IP, userAgent string) (AuthResult, error) {
	attemptID = strings.TrimSpace(attemptID)
	if !ids.SignInAttemptID(attemptID).Valid() {
		return AuthResult{}, apierr.New("invalid_grant", "sign-in attempt is invalid or expired")
	}
	if len(password) > security.MaxPasswordBytes {
		return AuthResult{}, apierr.New("invalid_credentials", "email or password is incorrect")
	}
	if err := s.allowRateLimit(ctx, "sign_in_complete:ip", rateIdentity(ip), 30, time.Minute); err != nil {
		return AuthResult{}, err
	}
	attemptEmail, err := s.Store.Queries().GetSignInAttemptRateIdentity(ctx, db.GetSignInAttemptRateIdentityParams{ID: attemptID})
	if errors.Is(err, pgx.ErrNoRows) {
		return AuthResult{}, apierr.New("invalid_grant", "sign-in attempt is invalid or expired")
	}
	if err != nil {
		return AuthResult{}, err
	}
	if err := s.allowRateLimit(ctx, "login:account", attemptEmail, 10, time.Minute); err != nil {
		return AuthResult{}, err
	}
	if err := s.allowRateLimit(ctx, "login:pair", rateIdentity(ip)+":"+attemptEmail, 5, time.Minute); err != nil {
		return AuthResult{}, err
	}

	var user db.GetUserByIDRow
	var userID string
	var disposition *apierr.Error
	var authenticationErr *apierr.Error
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		attempt, err := q.LockSignInAttempt(ctx, db.LockSignInAttemptParams{ID: attemptID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("invalid_grant", "sign-in attempt is invalid or expired")
		}
		if err != nil {
			return err
		}
		if !attempt.ExpiresAt.Time.After(time.Now().UTC()) || attempt.ConsumedAt.Valid || attempt.LockedAt.Valid {
			return apierr.New("invalid_grant", "sign-in attempt is invalid or expired")
		}
		if !attempt.UserID.Valid {
			_, err = q.IncrementSignInAttemptFailure(ctx, db.IncrementSignInAttemptFailureParams{ID: attemptID, MaxFailures: int32(maxSignInFailures)})
			if err != nil {
				return err
			}
			authenticationErr = apierr.New("invalid_credentials", "email or password is incorrect")
			return nil
		}
		user, err = q.GetUserByID(ctx, db.GetUserByIDParams{ID: attempt.UserID.String})
		if err != nil {
			return err
		}
		if !s.Passwords.Verify(password, user.PasswordHash) {
			_, err = q.IncrementSignInAttemptFailure(ctx, db.IncrementSignInAttemptFailureParams{ID: attemptID, MaxFailures: int32(maxSignInFailures)})
			if err != nil {
				return err
			}
			authenticationErr = apierr.New("invalid_credentials", "email or password is incorrect")
			return nil
		}
		if user.Status == "pending" {
			disposition = apierr.New("EMAIL_VERIFICATION_REQUIRED", "verify your email before signing in")
		} else if user.Status != "active" {
			disposition = apierr.New("UNAUTHENTICATED", "this account is not active")
		} else if user.PasswordResetRequiredAt.Valid {
			disposition = apierr.New("PASSWORD_RESET_REQUIRED", "reset your password before signing in")
		}
		if disposition != nil {
			return q.ConsumeSignInAttempt(ctx, db.ConsumeSignInAttemptParams{ID: attemptID})
		}
		if s.Passwords.NeedsRehash(user.PasswordHash) {
			upgraded, hashErr := s.Passwords.Hash(password)
			if hashErr != nil {
				return hashErr
			}
			if err := q.UpdatePassword(ctx, db.UpdatePasswordParams{ID: user.ID, PasswordHash: upgraded}); err != nil {
				return err
			}
			if err := audit.Write(ctx, q, "public", user.ID, "auth.password.rehash", user.ID, "success"); err != nil {
				return err
			}
		}
		userID = user.ID
		return q.ConsumeSignInAttempt(ctx, db.ConsumeSignInAttemptParams{ID: attemptID})
	})
	if err != nil {
		return AuthResult{}, err
	}
	if authenticationErr != nil {
		return AuthResult{}, authenticationErr
	}
	if disposition != nil {
		return AuthResult{}, disposition
	}
	memberID := ""
	if s.Authorization != nil {
		member, memberErr := s.Authorization.GetMemberForUser(ctx, userID, DefaultSpaceID)
		if memberErr != nil {
			return AuthResult{}, memberErr
		}
		memberID = member.ID
	}
	tokens, err := s.Sessions.CreateForMember(ctx, userID, memberID, ip, userAgent, 1)
	if err != nil {
		return AuthResult{}, err
	}
	return AuthResult{User: toPublicUser(user.ID, user.Email, user.EmailVerifiedAt.Valid, user.Status, user.CreatedAt.Time), Tokens: &tokens}, nil
}

func (s *Service) allowLoginRateLimits(ctx context.Context, email string, ip net.IP) error {
	identity := rateIdentity(ip)
	for _, bucket := range []struct {
		kind, value string
		limit       int
		window      time.Duration
	}{
		{"login:ip", identity, 30, time.Minute},
		{"login:account", email, 10, time.Minute},
		{"login:pair", identity + ":" + email, 5, time.Minute},
	} {
		if err := s.allowRateLimit(ctx, bucket.kind, bucket.value, bucket.limit, bucket.window); err != nil {
			return err
		}
	}
	return nil
}

func nullableText(value string) pgtype.Text {
	if strings.TrimSpace(value) == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: value, Valid: true}
}
