package invitation

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/mail"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/store"
)

const tokenLifetime = 7 * 24 * time.Hour

type Service struct{ Store *store.Store }

type CreateInput struct {
	SpaceID   string
	Email     string
	MemberID  string
	ExpiresAt time.Time
}

type Invitation struct {
	ID              string
	SpaceID         string
	EmailNormalized string
	MemberID        string
	ExpiresAt       time.Time
	ConsumedAt      *time.Time
	CreatedAt       time.Time
}

// Create creates a single-use invitation token. The raw token is returned only
// to the caller; the database stores its one-way digest.
func (s *Service) Create(ctx context.Context, in CreateInput) (Invitation, string, error) {
	return s.create(ctx, "", "", in)
}

// CreateForActor records the invitation issuance in the same transaction as
// the hashed token. The caller must authorize the actor against the target
// Space before invoking this method.
func (s *Service) CreateForActor(ctx context.Context, actorType, actorID string, in CreateInput) (Invitation, string, error) {
	return s.create(ctx, actorType, actorID, in)
}

func (s *Service) create(ctx context.Context, actorType, actorID string, in CreateInput) (Invitation, string, error) {
	if s == nil || s.Store == nil {
		return Invitation{}, "", errors.New("invitation store is required")
	}
	email, err := normalizeEmail(in.Email)
	if err != nil {
		return Invitation{}, "", err
	}
	if strings.TrimSpace(in.SpaceID) == "" {
		return Invitation{}, "", apierr.New("VALIDATION_FAILED", "space_id is required")
	}
	expiresAt := in.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = time.Now().UTC().Add(tokenLifetime)
	}
	if !expiresAt.After(time.Now().UTC()) {
		return Invitation{}, "", apierr.New("VALIDATION_FAILED", "invitation expiry must be in the future")
	}
	raw, hash, err := newToken()
	if err != nil {
		return Invitation{}, "", err
	}
	var row db.InvitationToken
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		memberID := pgtype.Text{}
		if value := strings.TrimSpace(in.MemberID); value != "" {
			memberID = pgtype.Text{String: value, Valid: true}
		}
		row, err = q.CreateInvitationToken(ctx, db.CreateInvitationTokenParams{
			ID: string(ids.New[ids.InvitationID]("ivt")), SpaceID: in.SpaceID,
			EmailNormalized: pgtype.Text{String: email, Valid: true},
			MemberID:        memberID,
			TokenHash:       hash, ExpiresAt: pgtype.Timestamptz{Time: expiresAt.UTC(), Valid: true},
		})
		if err != nil {
			return err
		}
		if strings.TrimSpace(actorID) != "" {
			return audit.Write(ctx, q, actorType, actorID, "invitation.create", row.ID, "success")
		}
		return nil
	})
	if err != nil {
		return Invitation{}, "", err
	}
	return fromRow(row), raw, nil
}

// Consume atomically marks a valid token as used. A token can therefore be
// accepted by at most one concurrent caller.
func (s *Service) Consume(ctx context.Context, raw string) (Invitation, error) {
	if s == nil || s.Store == nil {
		return Invitation{}, errors.New("invitation store is required")
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Invitation{}, apierr.New("invalid_grant", "invitation token is invalid or expired")
	}
	sum := sha256.Sum256([]byte(raw))
	var row db.InvitationToken
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		var consumeErr error
		row, consumeErr = q.ConsumeInvitationToken(ctx, db.ConsumeInvitationTokenParams{TokenHash: sum[:]})
		return consumeErr
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Invitation{}, apierr.New("invalid_grant", "invitation token is invalid or expired")
	}
	if err != nil {
		return Invitation{}, err
	}
	return fromRow(row), nil
}

func newToken() (string, []byte, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", nil, err
	}
	raw := "iv_" + base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(raw))
	return raw, sum[:], nil
}

func normalizeEmail(value string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(value))
	parsed, err := mail.ParseAddress(email)
	if err != nil || parsed.Address != email || !strings.Contains(email, "@") {
		return "", apierr.New("VALIDATION_FAILED", "a valid email is required")
	}
	return email, nil
}

func fromRow(row db.InvitationToken) Invitation {
	var consumedAt *time.Time
	if row.ConsumedAt.Valid {
		v := row.ConsumedAt.Time
		consumedAt = &v
	}
	return Invitation{ID: row.ID, SpaceID: row.SpaceID, EmailNormalized: row.EmailNormalized, MemberID: row.MemberID.String, ExpiresAt: row.ExpiresAt.Time, ConsumedAt: consumedAt, CreatedAt: row.CreatedAt.Time}
}
