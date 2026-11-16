-- name: CreateAuditDelivery :one
INSERT INTO invoice_audit_deliveries (
    id, invoice_id, space_id, group_id, member_id, user_id, action, outcome, request_id, request_digest
)
VALUES (sqlc.arg(id), sqlc.arg(invoice_id), sqlc.arg(space_id), sqlc.arg(group_id), sqlc.arg(member_id),
        sqlc.narg(user_id), sqlc.arg(action), sqlc.arg(outcome), sqlc.arg(request_id), sqlc.narg(request_digest))
RETURNING *;

-- name: SetAuditDeliveryJob :exec
UPDATE invoice_audit_deliveries SET river_job_id = sqlc.arg(job_id) WHERE id = sqlc.arg(id);

-- name: LockAuditDelivery :one
SELECT * FROM invoice_audit_deliveries WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: StartAuditDeliveryAttempt :one
UPDATE invoice_audit_deliveries SET attempt_started_at = now(), destination_hash = sqlc.arg(destination_hash)
WHERE id = sqlc.arg(id) RETURNING *;

-- name: UpdateAuditDeliveryResult :exec
UPDATE invoice_audit_deliveries SET audit_id = sqlc.narg(audit_id), delivered_at = sqlc.narg(delivered_at),
    last_error = sqlc.narg(last_error), blocked = sqlc.arg(blocked), generation = sqlc.arg(generation),
    attempt_started_at = CASE WHEN sqlc.arg(reset_attempt)::boolean THEN NULL ELSE attempt_started_at END,
    destination_hash = CASE WHEN sqlc.arg(reset_attempt)::boolean THEN NULL ELSE destination_hash END
WHERE id = sqlc.arg(id) AND generation = sqlc.arg(previous_generation) AND audit_id IS NULL;

-- name: ListAuditDeliveries :many
SELECT d.id, d.invoice_id, d.action, d.outcome, d.request_id, d.created_at, d.audit_id, d.last_error,
    CASE WHEN d.audit_id IS NOT NULL THEN 'delivered'
         WHEN d.blocked THEN 'blocked'
         WHEN j.state IN ('discarded', 'cancelled') THEN 'failed'
         ELSE 'pending' END::text AS state
FROM invoice_audit_deliveries d LEFT JOIN river_job j ON j.id = d.river_job_id
WHERE (sqlc.arg(after_id)::text = '' OR d.id > sqlc.arg(after_id))
ORDER BY d.id LIMIT sqlc.arg(limit_count);
