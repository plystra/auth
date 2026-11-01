package account

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/factor"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/security"
)

const (
	signInAttemptLifetime = 10 * time.Minute
	maxSignInFailures     = 5
)

type SignInChallenge struct {
	AttemptID      string                        `json:"attempt_id"`
	NextStep       string                        `json:"next_step"`
	ExpiresAt      time.Time                     `json:"expires_at"`
	PasskeyOptions *protocol.CredentialAssertion `json:"passkey_options,omitempty"`
}

func (s *Service) BeginPasskeySignIn(ctx context.Context, in LoginInput) (SignInChallenge, error) {
	email := strings.TrimSpace(strings.ToLower(in.Email))
	if !validEmail(email) {
		return SignInChallenge{}, apierr.New("invalid_request", "a valid email is required")
	}
	if err := s.allowLoginRateLimits(ctx, email, in.IP); err != nil {
		return SignInChallenge{}, err
	}
	if s.Sessions == nil || s.Sessions.Factors == nil {
		return SignInChallenge{}, apierr.New("UNAVAILABLE", "passkey sign-in is unavailable")
	}
	options, sessionData, expiresAt, err := s.Sessions.Factors.BeginPasskeyLogin()
	if err != nil {
		return SignInChallenge{}, err
	}
	var userID pgtype.Text
	row, err := s.Store.Queries().GetUserByEmail(ctx, db.GetUserByEmailParams{EmailNormalized: email})
	if err == nil {
		userID = pgtype.Text{String: row.ID, Valid: true}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return SignInChallenge{}, err
	}
	attempt, err := s.Store.Queries().CreatePasskeySignInAttempt(ctx, db.CreatePasskeySignInAttemptParams{
		ID: string(ids.New[ids.SignInAttemptID]("sia")), UserID: userID,
		EmailNormalized: email, Ip: nullableText(rateIdentity(in.IP)), UserAgent: nullableText(in.UserAgent),
		ExpiresAt: pgtype.Timestamptz{Time: expiresAt, Valid: true}, PasskeySession: sessionData,
	})
	if err != nil {
		return SignInChallenge{}, err
	}
	return SignInChallenge{AttemptID: attempt.ID, NextStep: "passkey", ExpiresAt: expiresAt, PasskeyOptions: options}, nil
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

// CompleteSignIn checks the password step and either issues a session or
// advances the locked workflow to TOTP when the account has that factor.
func (s *Service) CompleteSignIn(ctx context.Context, attemptID, password string, ip net.IP, userAgent string) (AuthResult, error) {
	attemptID = strings.TrimSpace(attemptID)
	if !ids.SignInAttemptID(attemptID).Valid() {
		return AuthResult{}, apierr.New("invalid_grant", "sign-in attempt is invalid or expired")
	}
	if len(password) > security.MaxPasswordBytes {
		return AuthResult{}, apierr.New("invalid_credentials", "email or password is incorrect")
	}
	if err := s.allowSignInAttemptRateLimits(ctx, attemptID, ip); err != nil {
		return AuthResult{}, err
	}

	var user db.GetUserByIDRow
	var userID string
	var challengeExpires time.Time
	var requiresTOTP bool
	var disposition *apierr.Error
	var authenticationErr *apierr.Error
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		attempt, err := q.LockSignInAttempt(ctx, db.LockSignInAttemptParams{ID: attemptID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("invalid_grant", "sign-in attempt is invalid or expired")
		}
		if err != nil {
			return err
		}
		if attempt.Method != "password" || !attempt.ExpiresAt.Time.After(time.Now().UTC()) || attempt.ConsumedAt.Valid || attempt.LockedAt.Valid || attempt.PasswordVerifiedAt.Valid {
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
		factorCount, err := q.CountTOTPFactors(ctx, db.CountTOTPFactorsParams{UserID: user.ID})
		if err != nil {
			return err
		}
		if factorCount > 0 {
			if s.Sessions == nil || s.Sessions.Factors == nil {
				return apierr.New("UNAVAILABLE", "TOTP verification is unavailable")
			}
			if err := q.MarkSignInPasswordVerified(ctx, db.MarkSignInPasswordVerifiedParams{ID: attemptID}); err != nil {
				return err
			}
			requiresTOTP = true
			challengeExpires = attempt.ExpiresAt.Time
			return nil
		}
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
	if requiresTOTP {
		return AuthResult{User: toPublicUser(user.ID, user.Email, user.EmailVerifiedAt.Valid, user.Status, user.CreatedAt.Time), AttemptID: attemptID, NextStep: "totp", ExpiresAt: &challengeExpires}, nil
	}
	memberID, err := s.defaultMemberID(ctx, userID)
	if err != nil {
		return AuthResult{}, err
	}
	tokens, err := s.Sessions.CreateForMember(ctx, userID, memberID, ip, userAgent, 1)
	if err != nil {
		return AuthResult{}, err
	}
	return AuthResult{User: toPublicUser(user.ID, user.Email, user.EmailVerifiedAt.Valid, user.Status, user.CreatedAt.Time), Tokens: &tokens}, nil
}

func (s *Service) CompleteSignInTOTP(ctx context.Context, attemptID, code string, ip net.IP, userAgent string) (AuthResult, error) {
	attemptID = strings.TrimSpace(attemptID)
	if !ids.SignInAttemptID(attemptID).Valid() {
		return AuthResult{}, apierr.New("invalid_grant", "sign-in attempt is invalid or expired")
	}
	if err := s.allowSignInAttemptRateLimits(ctx, attemptID, ip); err != nil {
		return AuthResult{}, err
	}
	if s.Sessions == nil || s.Sessions.Factors == nil {
		return AuthResult{}, apierr.New("UNAVAILABLE", "TOTP verification is unavailable")
	}
	var user db.GetUserByIDRow
	var authenticationErr *apierr.Error
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		attempt, err := q.LockSignInAttempt(ctx, db.LockSignInAttemptParams{ID: attemptID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("invalid_grant", "sign-in attempt is invalid or expired")
		}
		if err != nil {
			return err
		}
		if attempt.Method != "password" || !attempt.ExpiresAt.Time.After(time.Now().UTC()) || attempt.ConsumedAt.Valid || attempt.LockedAt.Valid || !attempt.PasswordVerifiedAt.Valid || !attempt.UserID.Valid {
			return apierr.New("invalid_grant", "sign-in attempt is invalid or expired")
		}
		user, err = q.GetUserByID(ctx, db.GetUserByIDParams{ID: attempt.UserID.String})
		if err != nil {
			return err
		}
		if user.Status != "active" || user.DisabledAt.Valid || user.PasswordResetRequiredAt.Valid {
			return apierr.New("UNAUTHENTICATED", "this account is not active")
		}
		factorCount, err := q.CountTOTPFactors(ctx, db.CountTOTPFactorsParams{UserID: user.ID})
		if err != nil {
			return err
		}
		if factorCount == 0 {
			return apierr.New("invalid_grant", "sign-in attempt is invalid or expired")
		}
		if err := s.Sessions.Factors.VerifyTOTPTxRateLimited(ctx, q, user.ID, "", code, time.Now().UTC()); err != nil {
			var public *apierr.Error
			if !errors.Is(err, factor.ErrInvalidCode) && (!errors.As(err, &public) || public.Code != "rate_limited") {
				return err
			}
			if _, err := q.IncrementSignInAttemptFailure(ctx, db.IncrementSignInAttemptFailureParams{ID: attemptID, MaxFailures: int32(maxSignInFailures)}); err != nil {
				return err
			}
			if public != nil {
				authenticationErr = public
			} else {
				authenticationErr = apierr.New("invalid_credentials", "the one-time code is invalid")
			}
			return nil
		}
		return q.ConsumeSignInAttempt(ctx, db.ConsumeSignInAttemptParams{ID: attemptID})
	})
	if err != nil {
		return AuthResult{}, err
	}
	if authenticationErr != nil {
		return AuthResult{}, authenticationErr
	}
	memberID, err := s.defaultMemberID(ctx, user.ID)
	if err != nil {
		return AuthResult{}, err
	}
	tokens, err := s.Sessions.CreateForMemberWithMethods(ctx, user.ID, memberID, ip, userAgent, 2, []string{"pwd", "otp"})
	if err != nil {
		return AuthResult{}, err
	}
	return AuthResult{User: toPublicUser(user.ID, user.Email, user.EmailVerifiedAt.Valid, user.Status, user.CreatedAt.Time), Tokens: &tokens}, nil
}

func (s *Service) CompletePasskeySignIn(ctx context.Context, attemptID string, response json.RawMessage, ip net.IP, userAgent string) (AuthResult, error) {
	attemptID = strings.TrimSpace(attemptID)
	if !ids.SignInAttemptID(attemptID).Valid() {
		return AuthResult{}, apierr.New("invalid_grant", "sign-in attempt is invalid or expired")
	}
	if err := s.allowSignInAttemptRateLimits(ctx, attemptID, ip); err != nil {
		return AuthResult{}, err
	}
	if s.Sessions == nil || s.Sessions.Factors == nil {
		return AuthResult{}, apierr.New("UNAVAILABLE", "passkey sign-in is unavailable")
	}
	var user db.GetUserByIDRow
	var authenticationErr *apierr.Error
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		attempt, err := q.LockSignInAttempt(ctx, db.LockSignInAttemptParams{ID: attemptID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("invalid_grant", "sign-in attempt is invalid or expired")
		}
		if err != nil {
			return err
		}
		if attempt.Method != "passkey" || !attempt.ExpiresAt.Time.After(time.Now().UTC()) || attempt.ConsumedAt.Valid || attempt.LockedAt.Valid {
			return apierr.New("invalid_grant", "sign-in attempt is invalid or expired")
		}
		if !attempt.UserID.Valid {
			if _, err := q.IncrementSignInAttemptFailure(ctx, db.IncrementSignInAttemptFailureParams{ID: attemptID, MaxFailures: int32(maxSignInFailures)}); err != nil {
				return err
			}
			if err := q.ConsumeSignInAttempt(ctx, db.ConsumeSignInAttemptParams{ID: attemptID}); err != nil {
				return err
			}
			authenticationErr = apierr.New("invalid_credentials", "passkey is invalid")
			return nil
		}
		user, err = q.GetUserByID(ctx, db.GetUserByIDParams{ID: attempt.UserID.String})
		if err != nil {
			return err
		}
		if user.Status != "active" || user.DisabledAt.Valid || user.PasswordResetRequiredAt.Valid {
			if _, err := q.IncrementSignInAttemptFailure(ctx, db.IncrementSignInAttemptFailureParams{ID: attemptID, MaxFailures: int32(maxSignInFailures)}); err != nil {
				return err
			}
			if err := q.ConsumeSignInAttempt(ctx, db.ConsumeSignInAttemptParams{ID: attemptID}); err != nil {
				return err
			}
			authenticationErr = apierr.New("invalid_credentials", "passkey is invalid")
			return nil
		}
		err = s.Sessions.Factors.VerifyPasskeyTx(ctx, q, user.ID, attempt.PasskeySession, response)
		var public *apierr.Error
		if errors.Is(err, factor.ErrInvalidPasskey) || errors.Is(err, factor.ErrClonedPasskey) || (errors.As(err, &public) && public.Code == "UNAUTHENTICATED") {
			if _, failureErr := q.IncrementSignInAttemptFailure(ctx, db.IncrementSignInAttemptFailureParams{ID: attemptID, MaxFailures: int32(maxSignInFailures)}); failureErr != nil {
				return failureErr
			}
			if errors.Is(err, factor.ErrClonedPasskey) {
				if auditErr := audit.Write(ctx, q, "user", user.ID, "factor.passkey.clone_detected", user.ID, "failure"); auditErr != nil {
					return auditErr
				}
			}
			if consumeErr := q.ConsumeSignInAttempt(ctx, db.ConsumeSignInAttemptParams{ID: attemptID}); consumeErr != nil {
				return consumeErr
			}
			authenticationErr = apierr.New("invalid_credentials", "passkey is invalid")
			return nil
		}
		if err != nil {
			return err
		}
		if err := q.ConsumeSignInAttempt(ctx, db.ConsumeSignInAttemptParams{ID: attemptID}); err != nil {
			return err
		}
		return audit.Write(ctx, q, "user", user.ID, "factor.passkey.sign_in", user.ID, "success")
	})
	if err != nil {
		return AuthResult{}, err
	}
	if authenticationErr != nil {
		return AuthResult{}, authenticationErr
	}
	memberID, err := s.defaultMemberID(ctx, user.ID)
	if err != nil {
		return AuthResult{}, err
	}
	tokens, err := s.Sessions.CreateForMemberWithMethods(ctx, user.ID, memberID, ip, userAgent, 2, []string{"webauthn"})
	if err != nil {
		return AuthResult{}, err
	}
	return AuthResult{User: toPublicUser(user.ID, user.Email, user.EmailVerifiedAt.Valid, user.Status, user.CreatedAt.Time), Tokens: &tokens}, nil
}

func (s *Service) allowSignInAttemptRateLimits(ctx context.Context, attemptID string, ip net.IP) error {
	if err := s.allowRateLimit(ctx, "sign_in_complete:ip", rateIdentity(ip), 30, time.Minute); err != nil {
		return err
	}
	attemptEmail, err := s.Store.Queries().GetSignInAttemptRateIdentity(ctx, db.GetSignInAttemptRateIdentityParams{ID: attemptID})
	if errors.Is(err, pgx.ErrNoRows) {
		return apierr.New("invalid_grant", "sign-in attempt is invalid or expired")
	}
	if err != nil {
		return err
	}
	if err := s.allowRateLimit(ctx, "login:account", attemptEmail, 10, time.Minute); err != nil {
		return err
	}
	return s.allowRateLimit(ctx, "login:pair", rateIdentity(ip)+":"+attemptEmail, 5, time.Minute)
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
