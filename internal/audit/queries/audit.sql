-- name: AppendAudit :exec
INSERT INTO audit_logs (id, actor_type, actor_id, action, resource_type, resource_id, outcome, request_id, metadata)
VALUES (sqlc.arg(id), sqlc.arg(actor_type), sqlc.narg(actor_id), sqlc.arg(action), sqlc.narg(resource_type), sqlc.narg(resource_id), sqlc.arg(outcome), sqlc.narg(request_id), COALESCE(sqlc.narg(metadata), '{}'::jsonb));

-- name: ListAudit :many
SELECT id, occurred_at, actor_type, actor_id, action, resource_type, resource_id, outcome, request_id, metadata FROM audit_logs ORDER BY occurred_at DESC LIMIT sqlc.arg(limit_count) OFFSET sqlc.arg(offset_count);
