-- name: CreateEmailVerificationToken :exec
INSERT INTO email_verification_tokens (id, user_id, token_hash, expires_at) VALUES (sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(token_hash), sqlc.arg(expires_at));

-- name: ConsumeEmailVerificationToken :one
UPDATE email_verification_tokens SET consumed_at = now() WHERE token_hash = sqlc.arg(token_hash) AND consumed_at IS NULL AND expires_at > now() RETURNING user_id;

-- name: CreatePasswordResetToken :exec
INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at) VALUES (sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(token_hash), sqlc.arg(expires_at));

-- name: ConsumePasswordResetToken :one
UPDATE password_reset_tokens SET consumed_at = now() WHERE token_hash = sqlc.arg(token_hash) AND consumed_at IS NULL AND expires_at > now() RETURNING user_id;

-- name: CreateOutboxEvent :exec
INSERT INTO outbox_events (id, topic, payload) VALUES (sqlc.arg(id), sqlc.arg(topic), sqlc.arg(payload));
