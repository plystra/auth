-- name: CountOperators :one
SELECT count(*)::int FROM operators WHERE active;

-- name: CountActiveMemberBindingsForUser :one
SELECT count(*)::int
FROM user_members
WHERE user_id = sqlc.arg(user_id)
  AND status = 'active'
  AND revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at > now());

-- name: CreateOperator :exec
INSERT INTO operators (user_id, capabilities) VALUES (sqlc.arg(user_id), sqlc.arg(capabilities));

-- name: GetOperator :one
SELECT user_id, capabilities, active, created_at, last_step_up_at FROM operators WHERE user_id=sqlc.arg(user_id);

-- name: LockOperatorIdentity :one
SELECT o.user_id, o.capabilities, o.active, u.disabled_at, u.password_hash
FROM operators o JOIN users u ON u.id = o.user_id WHERE o.user_id = sqlc.arg(user_id)
FOR SHARE OF o, u;

-- name: LockOperatorBootstrap :exec
SELECT pg_advisory_xact_lock(723615832001);

-- name: LockUserForOperator :one
SELECT id, email, email_normalized, password_hash, email_verified_at, disabled_at, created_at, updated_at
FROM users WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: CountTOTPFactors :one
SELECT count(*)::int FROM factors WHERE user_id = sqlc.arg(user_id) AND kind = 'totp';

-- name: ListOperators :many
SELECT o.user_id, u.email, o.capabilities, o.active, o.created_at, o.last_step_up_at, u.disabled_at
FROM operators o JOIN users u ON u.id = o.user_id
ORDER BY o.user_id;

-- name: LockOperator :one
SELECT user_id, capabilities, active, created_at, last_step_up_at
FROM operators WHERE user_id = sqlc.arg(user_id) FOR UPDATE;

-- name: UpdateOperatorCapabilities :one
UPDATE operators SET capabilities = sqlc.arg(capabilities)
WHERE user_id = sqlc.arg(user_id) AND active
RETURNING user_id, capabilities, active, created_at, last_step_up_at;

-- name: CountFullCapabilityOperators :one
SELECT count(*)::int FROM operators WHERE active AND capabilities @> '["*"]'::jsonb;

-- name: DisableOperator :one
UPDATE operators SET active = false
WHERE user_id = sqlc.arg(user_id) AND active
RETURNING user_id, capabilities, active, created_at, last_step_up_at;
