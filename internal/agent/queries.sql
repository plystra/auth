-- name: GetAgentsGroupByOwner :one
SELECT id, space_id, name, parent_id, kind, owner_member_id, status, created_at
FROM groups
WHERE owner_member_id = sqlc.arg(owner_member_id) AND kind = 'agents' AND status <> 'removed'
LIMIT 1;

-- name: GetMemberForAgentOwner :one
SELECT id, space_id, name, type, status, version, home_group_id, expires_at
FROM members
WHERE id = sqlc.arg(member_id);

-- name: CreateAgentsGroup :one
INSERT INTO groups (id, space_id, name, parent_id, kind, owner_member_id, status)
VALUES (sqlc.arg(id), sqlc.arg(space_id), sqlc.arg(name), sqlc.narg(parent_id), 'agents', sqlc.arg(owner_member_id), 'active')
RETURNING id, space_id, name, parent_id, kind, owner_member_id, status, created_at;

-- name: CreateAgentMember :one
INSERT INTO members (
    id, space_id, name, kind, type, binding_policy, status, version,
    home_group_id, created_by_user_id, created_by_member_id, source, expires_at
)
VALUES (
    sqlc.arg(id), sqlc.arg(space_id), sqlc.arg(name), 'agent', 'agent', 'single', 'active', 1,
    sqlc.arg(home_group_id), sqlc.narg(created_by_user_id), sqlc.arg(created_by_member_id), sqlc.arg(source), sqlc.arg(expires_at)
)
RETURNING id, space_id, name, type, binding_policy, status, version, home_group_id,
          created_by_user_id, created_by_member_id, source, expires_at, deleted_at, created_at;

-- name: AddAgentToGroup :exec
INSERT INTO group_members (group_id, member_id, source)
VALUES (sqlc.arg(group_id), sqlc.arg(member_id), 'manual')
ON CONFLICT (group_id, member_id) DO NOTHING;

-- name: GetAgentMember :one
SELECT m.id, m.space_id, m.name, m.type, m.binding_policy, m.status, m.version,
       m.home_group_id, m.created_by_user_id, m.created_by_member_id, m.source,
       m.expires_at, m.deleted_at, m.created_at,
       g.owner_member_id, g.parent_id AS group_parent_id, g.status AS group_status
FROM members m
JOIN groups g ON g.id = m.home_group_id AND g.kind = 'agents'
WHERE m.id = sqlc.arg(member_id) AND m.type = 'agent';

-- name: ListAgentsForGroup :many
SELECT m.id, m.space_id, m.name, m.type, m.binding_policy, m.status, m.version,
       m.home_group_id, m.created_by_user_id, m.created_by_member_id, m.source,
       m.expires_at, m.deleted_at, m.created_at
FROM members m
JOIN group_members gm ON gm.member_id = m.id
WHERE gm.group_id = sqlc.arg(group_id) AND m.type = 'agent'
ORDER BY m.created_at, m.id;

-- name: StopAgentMember :exec
UPDATE members
SET status = 'suspended', version = version + 1
WHERE id = sqlc.arg(member_id) AND type = 'agent' AND status = 'active';

-- name: DeleteAgentMember :exec
UPDATE members
SET status = 'removed', deleted_at = now(), version = version + 1
WHERE id = sqlc.arg(member_id) AND type = 'agent' AND status <> 'removed';

-- name: StopAgentsInGroup :exec
UPDATE members m
SET status = 'suspended', version = version + 1
FROM group_members gm
WHERE gm.member_id = m.id AND gm.group_id = sqlc.arg(group_id)
  AND m.type = 'agent' AND m.status = 'active';

-- name: StopAgentSubtree :exec
WITH RECURSIVE tree AS (
    SELECT groups.id FROM groups WHERE groups.id = sqlc.arg(group_id)
    UNION ALL
    SELECT g.id FROM groups g JOIN tree t ON g.parent_id = t.id
)
UPDATE members m
SET status = 'suspended', version = version + 1
FROM group_members gm
JOIN tree t ON t.id = gm.group_id
WHERE gm.member_id = m.id AND m.type = 'agent' AND m.status = 'active';

-- name: DeleteAgentSubtree :exec
WITH RECURSIVE tree AS (
    SELECT groups.id FROM groups WHERE groups.id = sqlc.arg(group_id)
    UNION ALL
    SELECT g.id FROM groups g JOIN tree t ON g.parent_id = t.id
)
UPDATE members m
SET status = 'removed', deleted_at = now(), version = version + 1
FROM group_members gm
JOIN tree t ON t.id = gm.group_id
WHERE gm.member_id = m.id AND m.type = 'agent' AND m.status <> 'removed';

-- name: RemoveAgentGroupSubtree :exec
WITH RECURSIVE tree AS (
    SELECT groups.id FROM groups WHERE groups.id = sqlc.arg(group_id)
    UNION ALL
    SELECT g.id FROM groups g JOIN tree t ON g.parent_id = t.id
)
UPDATE groups SET status = 'removed'
WHERE groups.id IN (SELECT tree.id FROM tree) AND kind = 'agents' AND status <> 'removed';

-- name: CreateAgentCredential :one
INSERT INTO agent_credentials (id, member_id, kind, prefix, secret_hash, family_id, expires_at)
VALUES (sqlc.arg(id), sqlc.arg(member_id), 'key', sqlc.arg(prefix), sqlc.arg(secret_hash), sqlc.narg(family_id), sqlc.arg(expires_at))
RETURNING id, member_id, kind, prefix, secret_hash, family_id, expires_at, revoked_at, last_used_at, created_at;

-- name: GetAgentCredentialByPrefix :one
SELECT c.id, c.member_id, c.kind, c.prefix, c.secret_hash, c.family_id, c.expires_at,
       c.revoked_at, c.last_used_at, c.created_at, m.space_id, m.status AS member_status,
       m.type, m.home_group_id, m.created_by_member_id
FROM agent_credentials c
JOIN members m ON m.id = c.member_id
WHERE c.prefix = sqlc.arg(prefix)
LIMIT 1;

-- name: TouchAgentCredential :exec
UPDATE agent_credentials SET last_used_at = now()
WHERE id = sqlc.arg(id) AND revoked_at IS NULL;

-- name: RevokeAgentCredentials :exec
UPDATE agent_credentials SET revoked_at = now()
WHERE member_id = sqlc.arg(member_id) AND revoked_at IS NULL;

-- name: ListActiveAgentCredentials :many
SELECT id, member_id, kind, prefix, family_id, expires_at, revoked_at, last_used_at, created_at
FROM agent_credentials
WHERE member_id = sqlc.arg(member_id) AND revoked_at IS NULL
ORDER BY created_at, id;

-- name: GetMemberVersion :one
SELECT version FROM members WHERE id = sqlc.arg(member_id);

-- name: CanManageAgent :one
WITH RECURSIVE agent_groups AS (
    SELECT g.id
    FROM groups g
    WHERE g.owner_member_id = sqlc.arg(owner_member_id)
      AND g.kind = 'agents'
      AND g.status <> 'removed'
    UNION ALL
    SELECT child.id
    FROM groups child
    JOIN agent_groups parent ON child.parent_id = parent.id
    WHERE child.kind = 'agents'
      AND child.status <> 'removed'
)
SELECT EXISTS (
    SELECT 1
    FROM members target
    WHERE target.id = sqlc.arg(target_member_id)
      AND target.type = 'agent'
      AND (target.id = sqlc.arg(owner_member_id) OR target.home_group_id IN (SELECT id FROM agent_groups))
) AS can_manage;
