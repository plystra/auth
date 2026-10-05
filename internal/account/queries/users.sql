-- name: CreateUser :one
INSERT INTO users (id, email, email_normalized, password_hash)
VALUES (sqlc.arg(id), sqlc.arg(email), sqlc.arg(email_normalized), sqlc.arg(password_hash))
RETURNING id, email, email_normalized, password_hash, email_verified_at, disabled_at, created_at, updated_at;

-- name: GetUserByEmail :one
SELECT id, email, email_normalized, password_hash, email_verified_at, disabled_at, created_at, updated_at
FROM users WHERE email_normalized = sqlc.arg(email_normalized) LIMIT 1;

-- name: GetUserByID :one
SELECT id, email, email_normalized, password_hash, email_verified_at, disabled_at, created_at, updated_at
FROM users WHERE id = sqlc.arg(id) LIMIT 1;

-- name: MarkEmailVerified :exec
UPDATE users SET email_verified_at = now(), updated_at = now() WHERE id = sqlc.arg(id);

-- name: UpdatePassword :exec
UPDATE users SET password_hash = sqlc.arg(password_hash), updated_at = now() WHERE id = sqlc.arg(id);
