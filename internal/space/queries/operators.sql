-- name: CountOperators :one
SELECT count(*)::int FROM operators WHERE active;

-- name: CreateOperator :exec
INSERT INTO operators (user_id, capabilities) VALUES (sqlc.arg(user_id), sqlc.arg(capabilities));

-- name: GetOperator :one
SELECT user_id, capabilities, active, created_at, last_step_up_at FROM operators WHERE user_id=sqlc.arg(user_id);
