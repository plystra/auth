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

type OAuthClient struct {
	ID               string
	SpaceID          string
	Name             string
	ClientID         string
	RedirectURIs     []string
	AllowedScopes    []string
	ClientSecretHash []byte
}

type AuthorizationCode struct {
	ID                  string
	ApplicationID       string
	UserID              string
	MemberID            string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	Scope               string
	Nonce               string
	Resource            string
	ExpiresAt           time.Time
}

type CreateAuthorizationCodeInput struct {
	ID                  string
	ApplicationID       string
	UserID              string
	MemberID            string
	RedirectURI         string
	CodeHash            []byte
	CodeChallenge       string
	CodeChallengeMethod string
	Scope               string
	Nonce               string
	Resource            string
	ExpiresAt           time.Time
}
type Key struct {
	ID                    string
	ApplicationID         string
	ClientID              string
	SpaceID               string
	Scopes                []string
	AllowSubjectAssertion bool
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
	return Key{ID: row.ID, ApplicationID: row.ApplicationID, ClientID: row.ClientID, SpaceID: row.SpaceID, Scopes: scopes, AllowSubjectAssertion: row.AllowSubjectAssertion}, nil
}

func (s *Service) OAuthClient(ctx context.Context, clientID string) (OAuthClient, error) {
	row, err := s.Store.Queries().GetApplicationByClientID(ctx, db.GetApplicationByClientIDParams{ClientID: clientID})
	if errors.Is(err, pgx.ErrNoRows) {
		return OAuthClient{}, apierr.New("invalid_request", "client_id is not registered")
	}
	if err != nil {
		return OAuthClient{}, err
	}
	var redirectURIs, allowedScopes []string
	if err := json.Unmarshal(row.RedirectUris, &redirectURIs); err != nil {
		return OAuthClient{}, apierr.New("temporarily_unavailable", "client metadata is invalid")
	}
	if err := json.Unmarshal(row.AllowedScopes, &allowedScopes); err != nil {
		return OAuthClient{}, apierr.New("temporarily_unavailable", "client metadata is invalid")
	}
	return OAuthClient{ID: row.ID, SpaceID: row.SpaceID, Name: row.Name, ClientID: row.ClientID, RedirectURIs: redirectURIs, AllowedScopes: allowedScopes, ClientSecretHash: row.ClientSecretHash}, nil
}

func (s *Service) CreateAuthorizationCode(ctx context.Context, in CreateAuthorizationCodeInput) error {
	return s.Store.InTx(ctx, func(q *db.Queries) error {
		return q.CreateAuthorizationCode(ctx, db.CreateAuthorizationCodeParams{
			ID: in.ID, ApplicationID: in.ApplicationID, UserID: in.UserID,
			MemberID: nullableText(in.MemberID), RedirectUri: in.RedirectURI,
			CodeHash: in.CodeHash, CodeChallenge: pgtype.Text{String: in.CodeChallenge, Valid: true},
			CodeChallengeMethod: pgtype.Text{String: in.CodeChallengeMethod, Valid: true}, Scope: in.Scope,
			Nonce: nullableText(in.Nonce), Resource: nullableText(in.Resource), ExpiresAt: pgtype.Timestamptz{Time: in.ExpiresAt, Valid: true},
		})
	})
}

func (s *Service) ConsumeAuthorizationCode(ctx context.Context, codeHash []byte, applicationID, redirectURI string) (AuthorizationCode, error) {
	var out AuthorizationCode
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		row, err := q.ConsumeAuthorizationCode(ctx, db.ConsumeAuthorizationCodeParams{CodeHash: codeHash, ApplicationID: applicationID, RedirectUri: redirectURI})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apierr.New("invalid_grant", "authorization code is invalid or expired")
			}
			return err
		}
		out = AuthorizationCode{ID: row.ID, ApplicationID: row.ApplicationID, UserID: row.UserID, RedirectURI: row.RedirectUri, Scope: row.Scope, ExpiresAt: row.ExpiresAt.Time}
		if row.MemberID.Valid {
			out.MemberID = row.MemberID.String
		}
		if row.CodeChallenge.Valid {
			out.CodeChallenge = row.CodeChallenge.String
		}
		if row.CodeChallengeMethod.Valid {
			out.CodeChallengeMethod = row.CodeChallengeMethod.String
		}
		if row.Nonce.Valid {
			out.Nonce = row.Nonce.String
		}
		if row.Resource.Valid {
			out.Resource = row.Resource.String
		}
		return nil
	})
	return out, err
}

func nullableText(value string) pgtype.Text {
	return pgtype.Text{String: value, Valid: value != ""}
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
