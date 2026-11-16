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

-- name: CreateGovernanceApprovalRequest :one
INSERT INTO approval_requests (
    id, kind, agent_member_id, approver_member_id, permission_key,
    resource_type, resource_id, resource_space_id, resource_group_id,
    resource_owner_member_id, operation, request_details, request_digest, reason, expires_at
)
VALUES (
    sqlc.arg(id), 'governance', sqlc.arg(agent_member_id), sqlc.arg(approver_member_id), sqlc.arg(permission_key),
    'governance', sqlc.arg(resource_id), sqlc.arg(resource_space_id), sqlc.narg(resource_group_id),
    sqlc.narg(resource_owner_member_id), sqlc.arg(operation), sqlc.arg(request_details), sqlc.arg(request_digest), '', sqlc.arg(expires_at)
)
RETURNING *;

-- name: ListPendingApprovalRequestsForUser :many
WITH RECURSIVE pending AS (
    SELECT a.id, a.agent_member_id FROM approval_requests a
    JOIN user_members um ON um.member_id = a.approver_member_id
    JOIN users u ON u.id = um.user_id
    JOIN members approver ON approver.id = a.approver_member_id
    WHERE um.user_id = sqlc.arg(user_id)
      AND um.status = 'active' AND um.revoked_at IS NULL
      AND (um.expires_at IS NULL OR um.expires_at > now())
      AND u.status = 'active' AND u.disabled_at IS NULL
      AND approver.type = 'human' AND approver.status = 'active'
      AND a.status = 'pending' AND a.expires_at > now()
), chain AS (
    SELECT p.id AS approval_id, m.id, m.space_id, m.name, m.type, m.status,
           m.home_group_id, m.source, m.oauth_client_id, 0 AS depth, ARRAY[m.id] AS visited
    FROM pending p JOIN members m ON m.id = p.agent_member_id
    UNION ALL
    SELECT c.approval_id, m.id, m.space_id, m.name, m.type, m.status,
           m.home_group_id, m.source, m.oauth_client_id, c.depth + 1, c.visited || m.id
    FROM chain c
    JOIN groups g ON g.id = c.home_group_id AND g.kind = 'agents'
    JOIN members m ON m.id = g.owner_member_id AND m.space_id = c.space_id
    WHERE c.type = 'agent' AND c.depth < 64 AND NOT m.id = ANY(c.visited)
)
SELECT sqlc.embed(a), (
    SELECT jsonb_agg(jsonb_build_object(
        'id', c.id, 'space_id', c.space_id, 'name', c.name, 'type', c.type, 'status', c.status,
        'source', CASE WHEN c.type = 'agent' THEN c.source ELSE '' END,
        'oauth_client_id', c.oauth_client_id
    ) ORDER BY c.depth)
    FROM chain c WHERE c.approval_id = a.id
)::jsonb AS delegation_chain
FROM approval_requests a JOIN pending p ON p.id = a.id
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
  AND kind = 'business'
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
  AND kind = 'business'
  AND permission_key = sqlc.arg(permission_key)
  AND resource_type = sqlc.arg(resource_type)
  AND resource_id = sqlc.arg(resource_id)
  AND resource_space_id = sqlc.arg(resource_space_id)
  AND resource_group_id IS NOT DISTINCT FROM sqlc.narg(resource_group_id)
  AND resource_owner_member_id IS NOT DISTINCT FROM sqlc.narg(resource_owner_member_id)
  AND status IN ('pending', 'rejected') AND expires_at > now()
ORDER BY created_at DESC, id DESC LIMIT 1;
