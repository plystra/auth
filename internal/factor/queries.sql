-- name: CreateFactor :one
INSERT INTO factors (id, user_id, kind, name, secret_ciphertext, credential_id, public_key, counter) VALUES (sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(kind), sqlc.arg(name), sqlc.narg(secret_ciphertext), sqlc.narg(credential_id), sqlc.narg(public_key), COALESCE(sqlc.narg(counter), 0)) RETURNING id, user_id, kind, name, secret_ciphertext, credential_id, public_key, counter, created_at, last_used_at;

-- name: ListFactors :many
SELECT id, user_id, kind, name, secret_ciphertext, credential_id, public_key, counter, created_at, last_used_at FROM factors WHERE user_id = sqlc.arg(user_id) ORDER BY created_at;

-- name: TouchFactor :exec
UPDATE factors SET last_used_at = now(), counter = COALESCE(sqlc.narg(counter), counter) WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id);
