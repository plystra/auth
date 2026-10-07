-- name: LockSpaceForAuthorization :one
SELECT id, name, slug, parent_id, policy_version, created_at, status
FROM spaces
WHERE id = sqlc.arg(id)
FOR UPDATE;

-- name: LockGroupInSpaceForAuthorization :one
SELECT id, space_id, name, parent_id, kind, owner_member_id, status, created_at
FROM groups
WHERE id = sqlc.arg(id) AND space_id = sqlc.arg(space_id)
FOR UPDATE;

-- name: LockMemberForAuthorization :one
SELECT id, space_id, name, type, binding_policy, status, created_at
FROM members
WHERE id = sqlc.arg(id)
FOR UPDATE;
