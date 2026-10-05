package account

import (
	"context"
	"crypto/rand"
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
	"github.com/plystra/auth/internal/ids"
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
func (s *Service) VerifyEmail(ctx context.Context, raw string) error {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
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
func (s *Service) RequestPasswordReset(ctx context.Context, email string) (string, error) {
	u, e := s.Store.Queries().GetUserByEmail(ctx, db.GetUserByEmailParams{EmailNormalized: strings.ToLower(strings.TrimSpace(email))})
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
		return q.CreatePasswordResetToken(ctx, db.CreatePasswordResetTokenParams{ID: string(ids.New[ids.ID]("prt")), UserID: u.ID, TokenHash: hash, ExpiresAt: pgTime(time.Now().UTC().Add(time.Hour))})
	})
	return raw, e
}
func (s *Service) ResetPassword(ctx context.Context, raw, password string) error {
	if len(password) < 12 {
		return apierr.New("invalid_request", "password does not meet the configured minimum length")
	}
	hash, e := s.Passwords.Hash(password)
	if e != nil {
		return e
	}
	return s.Store.InTx(ctx, func(q *db.Queries) error {
		v, e := q.ConsumePasswordResetToken(ctx, db.ConsumePasswordResetTokenParams{TokenHash: sha256Bytes(raw)})
		if e != nil {
			return e
		}
		if e = q.UpdatePassword(ctx, db.UpdatePasswordParams{ID: v, PasswordHash: hash}); e != nil {
			return e
		}
		if e = q.RevokeUserSessions(ctx, db.RevokeUserSessionsParams{UserID: v}); e != nil {
			return e
		}
		return q.RevokeUserRefreshTokens(ctx, db.RevokeUserRefreshTokensParams{UserID: v})
	})
}
func sha256Bytes(v string) []byte { sum := sha256.Sum256([]byte(strings.TrimSpace(v))); return sum[:] }

func pgTime(t time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: t, Valid: true} }
