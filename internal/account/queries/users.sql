-- name: CreateUser :one
INSERT INTO users (id, email, email_normalized, password_hash, status)
VALUES (sqlc.arg(id), sqlc.arg(email), sqlc.arg(email_normalized), sqlc.arg(password_hash), sqlc.arg(status))
RETURNING id, email, email_normalized, password_hash, email_verified_at, disabled_at, status, password_reset_required_at, created_at, updated_at;

-- name: GetUserByEmail :one
SELECT id, email, email_normalized, password_hash, email_verified_at, disabled_at, status, password_reset_required_at, created_at, updated_at
FROM users WHERE email_normalized = sqlc.arg(email_normalized) LIMIT 1;

-- name: GetUserByID :one
SELECT id, email, email_normalized, password_hash, email_verified_at, disabled_at, status, password_reset_required_at, created_at, updated_at
FROM users WHERE id = sqlc.arg(id) LIMIT 1;

-- name: LockUserForStatus :one
SELECT id, email, email_normalized, password_hash, email_verified_at, disabled_at, status, password_reset_required_at, created_at, updated_at
FROM users WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: LockUserForAuthorization :one
SELECT id, status FROM users WHERE id = sqlc.arg(id) FOR NO KEY UPDATE;

-- name: MarkEmailVerified :one
UPDATE users SET email_verified_at = now(), status = 'active', updated_at = now()
WHERE id = sqlc.arg(id) AND status = 'pending'
RETURNING id;

-- name: SetUserStatus :exec
UPDATE users SET status = sqlc.arg(status), disabled_at = CASE WHEN sqlc.arg(status) = 'disabled' THEN now() ELSE NULL END, updated_at = now()
WHERE id = sqlc.arg(id);

-- name: RequirePasswordReset :exec
UPDATE users SET password_reset_required_at = COALESCE(password_reset_required_at, now()), updated_at = now()
WHERE id = sqlc.arg(id);

-- name: ClearPasswordResetRequired :exec
UPDATE users SET password_reset_required_at = NULL, updated_at = now()
WHERE id = sqlc.arg(id);

-- name: UpdatePassword :exec
UPDATE users SET password_hash = sqlc.arg(password_hash), updated_at = now() WHERE id = sqlc.arg(id);
