package idempotency

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/store"
)

const retention = 24 * time.Hour

type Reservation struct {
	ID         string
	Replay     bool
	Conflict   bool
	InProgress bool
	StatusCode int
	Headers    map[string][]string
	Body       []byte
}

type Service struct {
	Store *store.Store
}

func (s *Service) Reserve(ctx context.Context, scopeHash, method, path, key string, requestHash []byte) (Reservation, error) {
	if s == nil || s.Store == nil {
		return Reservation{}, errors.New("idempotency store is unavailable")
	}
	expiresAt := pgtype.Timestamptz{Time: time.Now().UTC().Add(retention), Valid: true}
	args := db.InsertIdempotencyKeyParams{
		ID: string(ids.New[ids.ID]("idk")), ScopeHash: scopeHash, Method: method, Path: path,
		IdempotencyKey: key, RequestHash: requestHash, ExpiresAt: expiresAt,
	}
	row, err := s.Store.Queries().InsertIdempotencyKey(ctx, args)
	if err == nil {
		return Reservation{ID: row.ID}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Reservation{}, err
	}
	row, err = s.Store.Queries().GetIdempotencyKey(ctx, db.GetIdempotencyKeyParams{ScopeHash: scopeHash, Method: method, Path: path, IdempotencyKey: key})
	if errors.Is(err, pgx.ErrNoRows) {
		if err := s.Store.Queries().DeleteExpiredIdempotencyKey(ctx, db.DeleteExpiredIdempotencyKeyParams{ScopeHash: scopeHash, Method: method, Path: path, IdempotencyKey: key}); err != nil {
			return Reservation{}, err
		}
		row, err = s.Store.Queries().InsertIdempotencyKey(ctx, args)
		if err == nil {
			return Reservation{ID: row.ID}, nil
		}
	}
	if err != nil {
		return Reservation{}, err
	}
	if !bytes.Equal(row.RequestHash, requestHash) {
		return Reservation{Conflict: true}, nil
	}
	if row.State == "completed" && row.StatusCode.Valid {
		return Reservation{Replay: true, StatusCode: int(row.StatusCode.Int32), Headers: decodeHeaders(row.ResponseHeaders), Body: row.ResponseBody}, nil
	}
	if row.State == "pending" && row.UpdatedAt.Valid && row.UpdatedAt.Time.Before(time.Now().UTC().Add(-time.Minute)) {
		claimed, claimErr := s.Store.Queries().ClaimStaleIdempotencyKey(ctx, db.ClaimStaleIdempotencyKeyParams{ID: row.ID, RequestHash: requestHash, ExpiresAt: expiresAt})
		if claimErr == nil {
			return Reservation{ID: claimed.ID}, nil
		}
		if !errors.Is(claimErr, pgx.ErrNoRows) {
			return Reservation{}, claimErr
		}
	}
	return Reservation{InProgress: true}, nil
}

func (s *Service) Complete(ctx context.Context, id string, statusCode int, headers map[string][]string, body []byte) error {
	if s == nil || s.Store == nil {
		return errors.New("idempotency store is unavailable")
	}
	encodedHeaders, err := json.Marshal(headers)
	if err != nil {
		return err
	}
	return s.Store.Queries().CompleteIdempotencyKey(ctx, db.CompleteIdempotencyKeyParams{
		ID: id, StatusCode: pgtype.Int4{Int32: int32(statusCode), Valid: true}, ResponseHeaders: encodedHeaders, ResponseBody: body,
	})
}

func decodeHeaders(encoded []byte) map[string][]string {
	var headers map[string][]string
	if err := json.Unmarshal(encoded, &headers); err != nil || headers == nil {
		return map[string][]string{}
	}
	return headers
}
