-- name: CreateApprovalRequest :one
INSERT INTO approval_requests (
    id, agent_member_id, approver_member_id, permission_key,
    resource_type, resource_id, resource_space_id, resource_group_id,
    resource_owner_member_id, request_digest, reason, expires_at
)
VALUES (
    sqlc.arg(id), sqlc.arg(agent_member_id), sqlc.arg(approver_member_id), sqlc.arg(permission_key),
    sqlc.arg(resource_type), sqlc.arg(resource_id), sqlc.arg(resource_space_id), sqlc.narg(resource_group_id),
    sqlc.narg(resource_owner_member_id), sqlc.arg(request_digest), sqlc.arg(reason), sqlc.arg(expires_at)
)
RETURNING *;

-- name: ListPendingApprovalRequestsForUser :many
SELECT a.* FROM approval_requests a
JOIN user_members um ON um.member_id = a.approver_member_id
WHERE um.user_id = sqlc.arg(user_id)
  AND um.status = 'active' AND um.revoked_at IS NULL
  AND (um.expires_at IS NULL OR um.expires_at > now())
  AND a.status = 'pending' AND a.expires_at > now()
ORDER BY a.created_at DESC, a.id DESC;

-- name: LockApprovalRequest :one
SELECT * FROM approval_requests WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: DecideApprovalRequest :one
UPDATE approval_requests
SET status = sqlc.arg(status), decided_by_user_id = sqlc.arg(user_id), decided_at = now(),
    approved_expires_at = CASE WHEN sqlc.arg(status) = 'approved' THEN now() + interval '15 minutes' ELSE NULL END
WHERE id = sqlc.arg(id) AND status = 'pending' AND expires_at > now()
RETURNING *;

-- name: FindApprovedApprovalRequest :one
SELECT * FROM approval_requests
WHERE agent_member_id = sqlc.arg(agent_member_id)
  AND permission_key = sqlc.arg(permission_key)
  AND resource_type = sqlc.arg(resource_type)
  AND resource_id = sqlc.arg(resource_id)
  AND resource_space_id = sqlc.arg(resource_space_id)
  AND resource_group_id IS NOT DISTINCT FROM sqlc.narg(resource_group_id)
  AND resource_owner_member_id IS NOT DISTINCT FROM sqlc.narg(resource_owner_member_id)
  AND status = 'approved' AND approved_expires_at > now()
ORDER BY decided_at DESC, id DESC LIMIT 1 FOR UPDATE;

-- name: ConsumeApprovedApprovalRequest :execrows
UPDATE approval_requests SET status = 'consumed', consumed_at = now()
WHERE id = sqlc.arg(id) AND status = 'approved' AND approved_expires_at > now();

-- name: FindPendingOrRejectedApprovalRequest :one
SELECT * FROM approval_requests
WHERE agent_member_id = sqlc.arg(agent_member_id)
  AND permission_key = sqlc.arg(permission_key)
  AND resource_type = sqlc.arg(resource_type)
  AND resource_id = sqlc.arg(resource_id)
  AND resource_space_id = sqlc.arg(resource_space_id)
  AND resource_group_id IS NOT DISTINCT FROM sqlc.narg(resource_group_id)
  AND resource_owner_member_id IS NOT DISTINCT FROM sqlc.narg(resource_owner_member_id)
  AND status IN ('pending', 'rejected') AND expires_at > now()
ORDER BY created_at DESC, id DESC LIMIT 1;
