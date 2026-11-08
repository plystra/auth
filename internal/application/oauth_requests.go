package application

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
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/secret"
)

type OAuthAuthorizationRequestInput struct {
	ApplicationID string
	RedirectURI   string
	CodeChallenge string
	Scopes        []string
	State         string
	Nonce         string
	Resource      string
}

type OAuthAuthorizationRequest struct {
	ID            string
	ApplicationID string
	RedirectURI   string
	CodeChallenge string
	Scopes        []string
	State         string
	Nonce         string
	Resource      string
	ExpiresAt     time.Time
}

func (s *Service) CreateOAuthAuthorizationRequest(ctx context.Context, in OAuthAuthorizationRequestInput) (secret.String, time.Time, error) {
	if s == nil || s.Store == nil {
		return "", time.Time{}, apierr.New("temporarily_unavailable", "authorization is unavailable")
	}
	if in.ApplicationID == "" || in.RedirectURI == "" || in.CodeChallenge == "" || len(in.Scopes) == 0 || in.State == "" || in.Nonce == "" || in.Resource == "" {
		return "", time.Time{}, apierr.New("invalid_request", "authorization request is incomplete")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	handle := secret.New("ply_arq_" + base64.RawURLEncoding.EncodeToString(raw))
	hash := sha256.Sum256([]byte(handle.Value()))
	expiresAt := time.Now().UTC().Add(5 * time.Minute)
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		return q.CreateOAuthAuthorizationRequest(ctx, db.CreateOAuthAuthorizationRequestParams{
			ID: string(ids.New[ids.ID]("arq")), RequestHash: hash[:], ApplicationID: in.ApplicationID,
			RedirectUri: in.RedirectURI, CodeChallenge: in.CodeChallenge,
			Scope: strings.Join(in.Scopes, " "), State: in.State, Nonce: in.Nonce,
			Resource: in.Resource, ExpiresAt: pgtype.Timestamptz{Time: expiresAt, Valid: true},
		})
	})
	if err != nil {
		return "", time.Time{}, err
	}
	return handle, expiresAt, nil
}

func (s *Service) LockOAuthAuthorizationRequestTx(ctx context.Context, q *db.Queries, handle secret.String) (OAuthAuthorizationRequest, error) {
	if q == nil || !strings.HasPrefix(handle.Value(), "ply_arq_") || len(handle.Value()) != len("ply_arq_")+43 {
		return OAuthAuthorizationRequest{}, apierr.New("invalid_request", "authorization request is invalid or expired")
	}
	hash := sha256.Sum256([]byte(handle.Value()))
	row, err := q.LockOAuthAuthorizationRequest(ctx, db.LockOAuthAuthorizationRequestParams{RequestHash: hash[:]})
	if errors.Is(err, pgx.ErrNoRows) {
		return OAuthAuthorizationRequest{}, apierr.New("invalid_request", "authorization request is invalid or expired")
	}
	if err != nil {
		return OAuthAuthorizationRequest{}, err
	}
	return OAuthAuthorizationRequest{
		ID: row.ID, ApplicationID: row.ApplicationID, RedirectURI: row.RedirectUri,
		CodeChallenge: row.CodeChallenge, Scopes: strings.Fields(row.Scope), State: row.State,
		Nonce: row.Nonce, Resource: row.Resource, ExpiresAt: row.ExpiresAt.Time,
	}, nil
}

func (s *Service) FinishOAuthAuthorizationRequestTx(ctx context.Context, q *db.Queries, id, decision string) error {
	if q == nil || (decision != "approved" && decision != "denied") {
		return apierr.New("invalid_request", "authorization decision is invalid")
	}
	updated, err := q.FinishOAuthAuthorizationRequest(ctx, db.FinishOAuthAuthorizationRequestParams{ID: id, Status: decision})
	if err != nil {
		return err
	}
	if updated != 1 {
		return apierr.New("invalid_request", "authorization request is invalid or expired")
	}
	return nil
}
