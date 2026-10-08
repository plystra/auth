package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/idempotency"
	"github.com/plystra/auth/internal/ids"
)

type requestTxKey struct{}

type requestTx struct {
	tx     pgx.Tx
	q      *db.Queries
	closed bool
	seq    uint64
}

// BeginIdempotency opens the request transaction used by the HTTP idempotency
// boundary. The returned context must be passed to the handler so all
// Store.InTx calls reuse this transaction.
func (s *Store) BeginIdempotency(ctx context.Context) (idempotency.Transaction, error) {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	return &requestTx{tx: tx, q: db.New(tx)}, nil
}

func (t *requestTx) Context(ctx context.Context) context.Context {
	return context.WithValue(ctx, requestTxKey{}, t)
}

func requestTransaction(ctx context.Context) *requestTx {
	t, _ := ctx.Value(requestTxKey{}).(*requestTx)
	return t
}

// WithoutRequestTransaction keeps request metadata while ensuring a security
// rate-limit counter commits independently of a failed idempotent request.
func WithoutRequestTransaction(ctx context.Context) context.Context {
	return context.WithValue(ctx, requestTxKey{}, nil)
}

func (t *requestTx) inTx(ctx context.Context, fn func(*db.Queries) error) error {
	t.seq++
	name := "plystra_auth_request_" + strconv.FormatUint(t.seq, 10)
	if _, err := t.tx.Exec(ctx, "SAVEPOINT "+name); err != nil {
		return err
	}
	if err := fn(t.q); err != nil {
		if _, rollbackErr := t.tx.Exec(ctx, "ROLLBACK TO SAVEPOINT "+name); rollbackErr != nil {
			return fmt.Errorf("%w (rollback to savepoint: %v)", err, rollbackErr)
		}
		_, _ = t.tx.Exec(ctx, "RELEASE SAVEPOINT "+name)
		return err
	}
	_, err := t.tx.Exec(ctx, "RELEASE SAVEPOINT "+name)
	return err
}

func (t *requestTx) Reserve(ctx context.Context, in idempotency.Request) (idempotency.Reservation, error) {
	if t.closed {
		return idempotency.Reservation{}, errors.New("idempotency transaction is closed")
	}
	expiresAt := pgtype.Timestamptz{Time: time.Now().UTC().Add(24 * time.Hour), Valid: true}
	row, err := t.q.InsertIdempotencyKey(ctx, db.InsertIdempotencyKeyParams{
		ID: string(ids.New[ids.ID]("idk")), ScopeHash: in.ScopeHash, Method: in.Method,
		Path: in.Path, IdempotencyKey: in.Key, RequestHash: in.RequestHash, ExpiresAt: expiresAt,
	})
	if err == nil {
		return idempotency.Reservation{ID: row.ID}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return idempotency.Reservation{}, err
	}
	row, err = t.q.GetIdempotencyKey(ctx, db.GetIdempotencyKeyParams{
		ScopeHash: in.ScopeHash, Method: in.Method, Path: in.Path, IdempotencyKey: in.Key,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		if err := t.q.DeleteExpiredIdempotencyKey(ctx, db.DeleteExpiredIdempotencyKeyParams{
			ScopeHash: in.ScopeHash, Method: in.Method, Path: in.Path, IdempotencyKey: in.Key,
		}); err != nil {
			return idempotency.Reservation{}, err
		}
		row, err = t.q.InsertIdempotencyKey(ctx, db.InsertIdempotencyKeyParams{
			ID: string(ids.New[ids.ID]("idk")), ScopeHash: in.ScopeHash, Method: in.Method,
			Path: in.Path, IdempotencyKey: in.Key, RequestHash: in.RequestHash, ExpiresAt: expiresAt,
		})
		if err == nil {
			return idempotency.Reservation{ID: row.ID}, nil
		}
	}
	if err != nil {
		return idempotency.Reservation{}, err
	}
	if !equalBytes(row.RequestHash, in.RequestHash) {
		return idempotency.Reservation{Conflict: true}, nil
	}
	if row.State == "completed" && row.StatusCode.Valid {
		return idempotency.Reservation{
			Replay: true, StatusCode: int(row.StatusCode.Int32),
			Headers: decodeHeaders(row.ResponseHeaders), Body: append([]byte(nil), row.ResponseBody...),
		}, nil
	}
	if row.State == "pending" && row.UpdatedAt.Valid && row.UpdatedAt.Time.Before(time.Now().UTC().Add(-time.Minute)) {
		claimed, claimErr := t.q.ClaimStaleIdempotencyKey(ctx, db.ClaimStaleIdempotencyKeyParams{
			ID: row.ID, RequestHash: in.RequestHash, ExpiresAt: expiresAt,
		})
		if claimErr == nil {
			return idempotency.Reservation{ID: claimed.ID}, nil
		}
		if !errors.Is(claimErr, pgx.ErrNoRows) {
			return idempotency.Reservation{}, claimErr
		}
	}
	return idempotency.Reservation{InProgress: true}, nil
}

func (t *requestTx) Complete(ctx context.Context, id string, response idempotency.Response) error {
	if t.closed {
		return errors.New("idempotency transaction is closed")
	}
	encodedHeaders, err := json.Marshal(response.Headers)
	if err != nil {
		return err
	}
	updated, err := t.q.CompleteIdempotencyKey(ctx, db.CompleteIdempotencyKeyParams{
		ID: id, StatusCode: pgtype.Int4{Int32: int32(response.StatusCode), Valid: true},
		ResponseHeaders: encodedHeaders, ResponseBody: response.Body,
	})
	if err != nil {
		return err
	}
	if updated != 1 {
		return fmt.Errorf("idempotency reservation %s was not pending", id)
	}
	return nil
}

func (t *requestTx) Commit(ctx context.Context) error {
	if t.closed {
		return errors.New("idempotency transaction is closed")
	}
	err := t.tx.Commit(ctx)
	t.closed = true
	return err
}

func (t *requestTx) Rollback(ctx context.Context) error {
	if t.closed {
		return nil
	}
	t.closed = true
	return t.tx.Rollback(ctx)
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func decodeHeaders(encoded []byte) map[string][]string {
	var headers map[string][]string
	if err := json.Unmarshal(encoded, &headers); err != nil || headers == nil {
		return map[string][]string{}
	}
	return headers
}
