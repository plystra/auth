-- name: CountOperators :one
SELECT count(*)::int FROM operators WHERE active;

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
