-- name: ListDefaultAssignablePermissionKeys :many
SELECT key FROM permissions
WHERE status = 'active' AND delegable = true
ORDER BY key;

-- name: CreateAssignRight :one
INSERT INTO assign_rights (
    id, holder_member_id, permission_keys, anchor_space_id, anchor_group_id,
    covers_subtree, can_redelegate, source, parent_id, granted_by_operator_user_id, expires_at
) VALUES (
    sqlc.arg(id), sqlc.arg(holder_member_id), sqlc.arg(permission_keys),
    sqlc.narg(anchor_space_id), sqlc.narg(anchor_group_id),
    sqlc.arg(covers_subtree), sqlc.arg(can_redelegate), sqlc.arg(source),
    sqlc.narg(parent_id), sqlc.narg(granted_by_operator_user_id), sqlc.narg(expires_at)
)
RETURNING id, holder_member_id, permission_keys, anchor_space_id, anchor_group_id,
    covers_subtree, can_redelegate, source, parent_id, granted_by_operator_user_id,
    expires_at, revoked_at, created_at;

-- name: ListActiveAssignRightsForHolder :many
SELECT id, holder_member_id, permission_keys, anchor_space_id, anchor_group_id,
    covers_subtree, can_redelegate, source, parent_id, granted_by_operator_user_id,
    expires_at, revoked_at, created_at
FROM assign_rights
WHERE holder_member_id = sqlc.arg(holder_member_id)
  AND revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at > now())
ORDER BY created_at, id;

-- name: LockActiveAssignRightsForHolder :many
SELECT id, holder_member_id, permission_keys, anchor_space_id, anchor_group_id,
    covers_subtree, can_redelegate, source, parent_id, granted_by_operator_user_id,
    expires_at, revoked_at, created_at
FROM assign_rights
WHERE holder_member_id = sqlc.arg(holder_member_id)
  AND revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at > now())
ORDER BY created_at, id
FOR UPDATE;
