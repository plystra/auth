package application

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/store"
)

type Service struct{ Store *store.Store }
type Key struct {
	ID            string
	ApplicationID string
	ClientID      string
	SpaceID       string
	Scopes        []string
}

func (s *Service) AuthenticateKey(ctx context.Context, raw string) (Key, error) {
	parts := strings.SplitN(raw, ".", 2)
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "ply_sk_") {
		return Key{}, apierr.New("unauthorized", "application API key is required")
	}
	row, e := s.Store.Queries().GetAPIKeyByPrefix(ctx, db.GetAPIKeyByPrefixParams{Prefix: parts[0]})
	if e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			return Key{}, apierr.New("unauthorized", "application API key is invalid")
		}
		return Key{}, e
	}
	sum := sha256.Sum256([]byte(parts[1]))
	if !hmac.Equal(sum[:], row.SecretHash) {
		return Key{}, apierr.New("unauthorized", "application API key is invalid")
	}
	if row.RevokedAt.Valid || (row.ExpiresAt.Valid && row.ExpiresAt.Time.Before(time.Now())) {
		return Key{}, apierr.New("unauthorized", "application API key is revoked or expired")
	}
	if e = s.Store.InTx(ctx, func(q *db.Queries) error {
		return q.TouchAPIKey(ctx, db.TouchAPIKeyParams{ID: row.ID})
	}); e != nil {
		return Key{}, e
	}
	var scopes []string
	_ = json.Unmarshal(row.Scopes, &scopes)
	return Key{ID: row.ID, ApplicationID: row.ApplicationID, ClientID: row.ClientID, SpaceID: row.SpaceID, Scopes: scopes}, nil
}
func GenerateSecret() (string, string, []byte, error) {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return "", "", nil, e
	}
	raw := base64.RawURLEncoding.EncodeToString(b)
	prefix := "ply_sk_" + raw[:10]
	sum := sha256.Sum256([]byte(raw))
	return prefix + "." + raw, prefix, sum[:], nil
}
func (s *Service) CreateKey(ctx context.Context, applicationID, name string, scopes []string, expires *time.Time) (string, error) {
	raw, prefix, hash, e := GenerateSecret()
	if e != nil {
		return "", e
	}
	_, e = s.Store.Queries().CreateAPIKey(ctx, db.CreateAPIKeyParams{ID: string(ids.New[ids.APIKeyID]("key")), ApplicationID: applicationID, Name: name, Prefix: prefix, SecretHash: hash, Scopes: mustJSON(scopes), ExpiresAt: nullableTime(expires)})
	return raw, e
}
func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
func nullableTime(t *time.Time) pgtype.Timestamptz {
	if t == nil {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: *t, Valid: true}
}
