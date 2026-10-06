-- name: InsertIdempotencyKey :one
INSERT INTO idempotency_keys (
    id, scope_hash, method, path, idempotency_key, request_hash, expires_at
)
VALUES (
    sqlc.arg(id), sqlc.arg(scope_hash), sqlc.arg(method), sqlc.arg(path),
    sqlc.arg(idempotency_key), sqlc.arg(request_hash), sqlc.arg(expires_at)
)
ON CONFLICT (scope_hash, method, path, idempotency_key) DO NOTHING
RETURNING id, scope_hash, method, path, idempotency_key, request_hash, state,
          status_code, response_headers, response_body, created_at, updated_at, expires_at;

-- name: GetIdempotencyKey :one
SELECT id, scope_hash, method, path, idempotency_key, request_hash, state,
       status_code, response_headers, response_body, created_at, updated_at, expires_at
FROM idempotency_keys
WHERE scope_hash = sqlc.arg(scope_hash)
  AND method = sqlc.arg(method)
  AND path = sqlc.arg(path)
  AND idempotency_key = sqlc.arg(idempotency_key)
  AND expires_at > now();

-- name: ClaimStaleIdempotencyKey :one
UPDATE idempotency_keys
SET state = 'pending', status_code = NULL, response_headers = '{}'::jsonb,
    response_body = NULL, request_hash = sqlc.arg(request_hash),
    updated_at = now(), expires_at = sqlc.arg(expires_at)
WHERE id = sqlc.arg(id)
  AND state = 'pending'
  AND updated_at < now() - interval '1 minute'
RETURNING id, scope_hash, method, path, idempotency_key, request_hash, state,
          status_code, response_headers, response_body, created_at, updated_at, expires_at;

-- name: CompleteIdempotencyKey :exec
UPDATE idempotency_keys
SET state = 'completed', status_code = sqlc.arg(status_code),
    response_headers = sqlc.arg(response_headers), response_body = sqlc.arg(response_body),
    updated_at = now()
WHERE id = sqlc.arg(id) AND state = 'pending' AND expires_at > now();

-- name: DeleteExpiredIdempotencyKey :exec
DELETE FROM idempotency_keys
WHERE scope_hash = sqlc.arg(scope_hash)
  AND method = sqlc.arg(method)
  AND path = sqlc.arg(path)
  AND idempotency_key = sqlc.arg(idempotency_key)
  AND expires_at <= now();
