package account

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/security"
)

func opaqueToken(prefix string) (string, []byte, error) {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return "", nil, e
	}
	raw := prefix + base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(raw))
	return raw, sum[:], nil
}
func (s *Service) CreateEmailVerification(ctx context.Context, userID string) (string, error) {
	raw, hash, e := opaqueToken("ev_")
	if e != nil {
		return "", e
	}
	e = s.Store.InTx(ctx, func(q *db.Queries) error {
		return q.CreateEmailVerificationToken(ctx, db.CreateEmailVerificationTokenParams{ID: string(ids.New[ids.ID]("evt")), UserID: userID, TokenHash: hash, ExpiresAt: pgTime(time.Now().UTC().Add(24 * time.Hour))})
	})
	return raw, e
}
func (s *Service) VerifyEmail(ctx context.Context, raw string, ips ...net.IP) error {
	raw = strings.TrimSpace(raw)
	sum := sha256.Sum256([]byte(raw))
	ip := rateIdentity(firstIP(ips))
	if err := s.allowRateLimit(ctx, "verify:ip", ip, 30, time.Hour); err != nil {
		return err
	}
	accountID := "token:" + base64.RawURLEncoding.EncodeToString(sum[:])
	if userID, err := s.Store.Queries().GetEmailVerificationTokenUser(ctx, db.GetEmailVerificationTokenUserParams{TokenHash: sum[:]}); err == nil {
		accountID = "account:" + userID
		if err := s.allowRateLimit(ctx, "verify:account", userID, 10, time.Hour); err != nil {
			return err
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err := s.allowRateLimit(ctx, "verify:pair", ip+":"+accountID, 5, time.Hour); err != nil {
		return err
	}
	var userID string
	e := s.Store.InTx(ctx, func(q *db.Queries) error {
		v, e := q.ConsumeEmailVerificationToken(ctx, db.ConsumeEmailVerificationTokenParams{TokenHash: sum[:]})
		if e != nil {
			return e
		}
		userID = v
		if _, e = q.MarkEmailVerified(ctx, db.MarkEmailVerifiedParams{ID: userID}); e != nil {
			return e
		}
		return audit.Write(ctx, q, "public", userID, "auth.email.verify", userID, "success")
	})
	if errors.Is(e, pgx.ErrNoRows) {
		return apierr.New("invalid_grant", "verification token is invalid or expired")
	}
	return e
}
func (s *Service) RequestPasswordReset(ctx context.Context, email string, ips ...net.IP) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	ip := rateIdentity(firstIP(ips))
	for _, bucket := range []struct {
		kind, value string
		limit       int
	}{
		{"reset:ip", ip, 30},
		{"reset:account", email, 10},
		{"reset:pair", ip + ":" + email, 5},
	} {
		if err := s.allowRateLimit(ctx, bucket.kind, bucket.value, bucket.limit, time.Hour); err != nil {
			return "", err
		}
	}
	u, e := s.Store.Queries().GetUserByEmail(ctx, db.GetUserByEmailParams{EmailNormalized: email})
	if e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			return "", nil
		}
		return "", e
	}
	raw, hash, e := opaqueToken("pr_")
	if e != nil {
		return "", e
	}
	e = s.Store.InTx(ctx, func(q *db.Queries) error {
		expiresAt := time.Now().UTC().Add(time.Hour)
		if err := q.CreatePasswordResetToken(ctx, db.CreatePasswordResetTokenParams{ID: string(ids.New[ids.ID]("prt")), UserID: u.ID, TokenHash: hash, ExpiresAt: pgTime(expiresAt)}); err != nil {
			return err
		}
		if s.Mailer != nil {
			return s.Mailer.EnqueuePasswordResetTx(ctx, q, email, secret.New(raw), expiresAt)
		}
		return nil
	})
	return raw, e
}
func (s *Service) ResetPassword(ctx context.Context, raw, password string, ips ...net.IP) error {
	raw = strings.TrimSpace(raw)
	tokenHash := sha256Bytes(raw)
	ip := rateIdentity(firstIP(ips))
	if err := s.allowRateLimit(ctx, "reset:ip", ip, 30, time.Hour); err != nil {
		return err
	}
	accountID := "token:" + base64.RawURLEncoding.EncodeToString(tokenHash)
	if userID, lookupErr := s.Store.Queries().GetPasswordResetTokenUser(ctx, db.GetPasswordResetTokenUserParams{TokenHash: tokenHash}); lookupErr == nil {
		accountID = "account:" + userID
		if err := s.allowRateLimit(ctx, "reset:account", userID, 10, time.Hour); err != nil {
			return err
		}
	} else if !errors.Is(lookupErr, pgx.ErrNoRows) {
		return lookupErr
	}
	if err := s.allowRateLimit(ctx, "reset:pair", ip+":"+accountID, 5, time.Hour); err != nil {
		return err
	}
	if len(password) < 12 {
		return apierr.New("invalid_request", "password does not meet the configured minimum length")
	}
	if len(password) > security.MaxPasswordBytes {
		return apierr.New("invalid_request", "password exceeds the maximum length")
	}
	hash, e := s.Passwords.Hash(password)
	if e != nil {
		return e
	}
	return s.Store.InTx(ctx, func(q *db.Queries) error {
		v, e := q.ConsumePasswordResetToken(ctx, db.ConsumePasswordResetTokenParams{TokenHash: tokenHash})
		if e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return apierr.New("invalid_grant", "password reset token is invalid or expired")
			}
			return e
		}
		if e = q.UpdatePassword(ctx, db.UpdatePasswordParams{ID: v, PasswordHash: hash}); e != nil {
			return e
		}
		if e = q.ClearPasswordResetRequired(ctx, db.ClearPasswordResetRequiredParams{ID: v}); e != nil {
			return e
		}
		if e = q.RevokeUserSessions(ctx, db.RevokeUserSessionsParams{UserID: v}); e != nil {
			return e
		}
		if e = q.RevokeUserRefreshTokens(ctx, db.RevokeUserRefreshTokensParams{UserID: v}); e != nil {
			return e
		}
		return audit.Write(ctx, q, "public", v, "auth.password.reset", v, "success")
	})
}
func firstIP(ips []net.IP) net.IP {
	if len(ips) == 0 {
		return nil
	}
	return ips[0]
}
func sha256Bytes(v string) []byte { sum := sha256.Sum256([]byte(strings.TrimSpace(v))); return sum[:] }

func pgTime(t time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: t, Valid: true} }
