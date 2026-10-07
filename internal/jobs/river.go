package jobs

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/plystra/auth/internal/db"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
)

// Client is the process-local River producer. Workers are added by the
// capability that owns a job; this producer is safe to use from business
// transactions without opening a second connection.
type Client struct {
	river *river.Client[pgx.Tx]
}

func NewClient(pool *pgxpool.Pool) (*Client, error) {
	client, err := river.NewClient(riverpgxv5.New(pool), &river.Config{})
	if err != nil {
		return nil, fmt.Errorf("configure river client: %w", err)
	}
	return &Client{river: client}, nil
}

// InsertTx enqueues args on the exact transaction owned by Store.InTx. A
// query set backed by the pool is rejected so callers cannot accidentally
// create a job outside the business transaction.
func (c *Client) InsertTx(ctx context.Context, q *db.Queries, args river.JobArgs) error {
	if c == nil || c.river == nil {
		return fmt.Errorf("river client is not configured")
	}
	tx, ok := q.Transaction()
	if !ok {
		return fmt.Errorf("river enqueue requires a store transaction")
	}
	if _, err := c.river.InsertTx(ctx, tx, args, nil); err != nil {
		return fmt.Errorf("enqueue river job: %w", err)
	}
	return nil
}
