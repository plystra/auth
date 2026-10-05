-- name: ConsumeRateLimit :one
INSERT INTO rate_limit_buckets (bucket_key, window_start, count) VALUES (sqlc.arg(bucket_key), sqlc.arg(window_start), 1) ON CONFLICT (bucket_key, window_start) DO UPDATE SET count = rate_limit_buckets.count + 1 RETURNING count;

-- name: PruneRateLimitBuckets :exec
DELETE FROM rate_limit_buckets WHERE window_start < now() - interval '2 days';
