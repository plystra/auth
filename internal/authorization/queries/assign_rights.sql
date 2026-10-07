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

-- name: RevokeAssignRight :exec
UPDATE assign_rights SET revoked_at = now()
WHERE id = sqlc.arg(id) AND revoked_at IS NULL;

-- name: GetAssignRight :one
SELECT id, holder_member_id, permission_keys, anchor_space_id, anchor_group_id,
    covers_subtree, can_redelegate, source, parent_id, granted_by_operator_user_id,
    expires_at, revoked_at, created_at
FROM assign_rights
WHERE id = sqlc.arg(id);

-- name: ListAssignRightsInSpace :many
SELECT ar.id, ar.holder_member_id, ar.permission_keys, ar.anchor_space_id, ar.anchor_group_id,
    ar.covers_subtree, ar.can_redelegate, ar.source, ar.parent_id, ar.granted_by_operator_user_id,
    ar.expires_at, ar.revoked_at, ar.created_at
FROM assign_rights ar
LEFT JOIN groups g ON g.id = ar.anchor_group_id
WHERE ar.revoked_at IS NULL
  AND (ar.expires_at IS NULL OR ar.expires_at > now())
  AND (ar.anchor_space_id = sqlc.arg(space_id) OR g.space_id = sqlc.arg(space_id))
ORDER BY ar.created_at, ar.id;
