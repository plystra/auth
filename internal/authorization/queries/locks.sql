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

-- name: SuspendAgentsCreatedByBinding :many
UPDATE members
SET status = 'suspended', version = version + 1
WHERE type = 'agent'
  AND created_by_user_id = sqlc.arg(user_id)
  AND created_by_member_id = sqlc.arg(member_id)
  AND status = 'active'
RETURNING id;

-- name: RevokeAgentCredentialsForMember :exec
UPDATE agent_credentials
SET revoked_at = now()
WHERE member_id = sqlc.arg(member_id) AND revoked_at IS NULL;

-- name: CountStandardRootGroups :one
SELECT count(*)::bigint
FROM groups
WHERE space_id = sqlc.arg(space_id)
  AND kind = 'standard'
  AND parent_id IS NULL
  AND status <> 'removed';

-- name: CreateStandardGroup :one
INSERT INTO groups (id, space_id, name, parent_id, kind, status)
VALUES (sqlc.arg(id), sqlc.arg(space_id), sqlc.arg(name), sqlc.narg(parent_id), 'standard', 'active')
RETURNING id, space_id, name, parent_id, kind, owner_member_id, status, created_at;
