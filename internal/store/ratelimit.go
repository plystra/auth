package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/db"
)

type RateLimiter struct{ Store *Store }

func (r RateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	start := time.Now().UTC().Truncate(window)
	var count int32
	err := r.Store.InTx(ctx, func(q *db.Queries) error {
		row, e := q.ConsumeRateLimit(ctx, db.ConsumeRateLimitParams{BucketKey: key, WindowStart: pgtype.Timestamptz{Time: start, Valid: true}})
		if e == nil {
			count = row
		}
		return e
	})
	return int(count) <= limit, err
}
