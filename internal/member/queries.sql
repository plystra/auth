-- name: CreateMember :one
INSERT INTO members (id, space_id, name, kind, type)
VALUES (sqlc.arg(id), sqlc.arg(space_id), sqlc.arg(name), sqlc.arg(kind), sqlc.arg(type))
RETURNING id, space_id, name, type, created_at;

-- name: CreateMemberWithPolicy :one
INSERT INTO members (id, space_id, name, kind, type, binding_policy)
VALUES (sqlc.arg(id), sqlc.arg(space_id), sqlc.arg(name), CASE sqlc.arg(type) WHEN 'human' THEN 'user' WHEN 'application' THEN 'service' ELSE sqlc.arg(type) END, sqlc.arg(type), sqlc.arg(binding_policy))
RETURNING id, space_id, name, type, binding_policy, status, created_at;

-- name: LinkUserMember :exec
INSERT INTO user_members (user_id, member_id) VALUES (sqlc.arg(user_id), sqlc.arg(member_id)) ON CONFLICT DO NOTHING;

-- name: CountOperatorsForUser :one
SELECT count(*)::int FROM operators WHERE user_id = sqlc.arg(user_id);

-- name: BindUserMember :exec
INSERT INTO user_members (user_id, member_id, status, expires_at, revoked_at)
VALUES (sqlc.arg(user_id), sqlc.arg(member_id), 'active', sqlc.narg(expires_at), NULL)
ON CONFLICT (user_id, member_id) DO UPDATE SET status = 'active', expires_at = EXCLUDED.expires_at, revoked_at = NULL;

-- name: RevokeUserMember :exec
UPDATE user_members SET status = 'revoked', revoked_at = now()
WHERE user_id = sqlc.arg(user_id) AND member_id = sqlc.arg(member_id) AND status = 'active';

-- name: GetUserMemberBinding :one
SELECT user_id, member_id, status, expires_at, revoked_at
FROM user_members WHERE user_id = sqlc.arg(user_id) AND member_id = sqlc.arg(member_id);

-- name: LockUserMemberBinding :one
SELECT user_id, member_id, status, expires_at, revoked_at
FROM user_members WHERE user_id = sqlc.arg(user_id) AND member_id = sqlc.arg(member_id)
FOR UPDATE;

-- name: CountActiveMemberBindings :one
SELECT count(*)::bigint FROM user_members
WHERE member_id = sqlc.arg(member_id) AND status = 'active' AND revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at > now());

-- name: ListMemberBindings :many
SELECT um.user_id, um.member_id, um.status, um.expires_at, um.revoked_at, u.email
FROM user_members um JOIN users u ON u.id = um.user_id
WHERE um.member_id = sqlc.arg(member_id)
ORDER BY um.created_at, um.user_id;

-- name: GetMemberForUser :one
SELECT m.id, m.space_id, m.name, m.type, m.binding_policy, m.status, m.created_at FROM members m JOIN user_members um ON um.member_id=m.id WHERE um.user_id=sqlc.arg(user_id) AND um.status = 'active' AND (um.expires_at IS NULL OR um.expires_at > now()) AND um.revoked_at IS NULL AND m.status = 'active' AND m.space_id=sqlc.arg(space_id) LIMIT 1;

-- name: ListMembersForUser :many
SELECT m.id, m.space_id, m.name, m.type, m.binding_policy, m.status, m.created_at
FROM members m
JOIN user_members um ON um.member_id = m.id
WHERE um.user_id = sqlc.arg(user_id)
  AND um.status = 'active'
  AND (um.expires_at IS NULL OR um.expires_at > now())
  AND um.revoked_at IS NULL
  AND m.status = 'active'
ORDER BY m.created_at, m.id;

-- name: ListMembersForUserByType :many
SELECT m.id, m.space_id, m.name, m.type, m.binding_policy, m.status, m.created_at
FROM members m
JOIN user_members um ON um.member_id = m.id
WHERE um.user_id = sqlc.arg(user_id)
  AND um.status = 'active'
  AND (um.expires_at IS NULL OR um.expires_at > now())
  AND um.revoked_at IS NULL
  AND m.status = 'active'
  AND m.type = sqlc.arg(member_type)
ORDER BY m.created_at, m.id;

-- name: ListMembersInSpace :many
SELECT id, space_id, name, type, binding_policy, status, created_at
FROM members WHERE space_id = sqlc.arg(space_id) AND status <> 'removed'
  AND (sqlc.narg(member_type)::text IS NULL OR type = sqlc.narg(member_type))
ORDER BY created_at, id;

-- name: ListGroupMembers :many
SELECT m.id, m.space_id, m.name, m.type, m.binding_policy, m.status
FROM members m
JOIN group_members gm ON gm.member_id = m.id AND gm.space_id = m.space_id
WHERE gm.group_id = sqlc.arg(group_id) AND gm.space_id = sqlc.arg(space_id)
  AND m.status <> 'removed'
ORDER BY m.created_at, m.id;

-- name: GetMemberInSpace :one
SELECT id, space_id, name, type, binding_policy, status, created_at
FROM members WHERE id = sqlc.arg(id) AND space_id = sqlc.arg(space_id);

-- name: GetMemberForAuthorization :one
SELECT id, space_id, name, type, binding_policy, status, created_at
FROM members
WHERE id = sqlc.arg(id);

-- name: ListMemberGroups :many
SELECT g.id, g.space_id, g.name, g.parent_id, g.kind, g.owner_member_id, g.status, g.created_at
FROM groups g
JOIN group_members gm ON gm.group_id = g.id
WHERE gm.member_id = sqlc.arg(member_id)
  AND g.space_id = sqlc.arg(space_id)
  AND g.status = 'active'
ORDER BY g.id;

-- name: GetGroupMember :one
SELECT group_id, member_id, space_id, source
FROM group_members
WHERE group_id = sqlc.arg(group_id) AND member_id = sqlc.arg(member_id);

-- name: AddGroupMember :exec
INSERT INTO group_members (group_id, member_id, space_id, source)
VALUES (sqlc.arg(group_id), sqlc.arg(member_id), sqlc.arg(space_id), sqlc.arg(source))
ON CONFLICT (group_id, member_id) DO NOTHING;

-- name: LockGroupSubtree :many
WITH RECURSIVE tree AS (
    SELECT groups.id, groups.space_id, groups.name, groups.parent_id, groups.kind, groups.owner_member_id, groups.status, groups.created_at
    FROM groups
    WHERE groups.id = sqlc.arg(group_id) AND groups.space_id = sqlc.arg(space_id)
    UNION ALL
    SELECT child.id, child.space_id, child.name, child.parent_id, child.kind, child.owner_member_id, child.status, child.created_at
    FROM groups child
    JOIN tree parent ON child.parent_id = parent.id
    WHERE child.space_id = sqlc.arg(space_id)
)
SELECT id, space_id, name, parent_id, kind, owner_member_id, status, created_at
FROM tree
ORDER BY id
FOR UPDATE;

-- name: ListMembersInGroupSubtree :many
WITH RECURSIVE tree AS (
    SELECT groups.id
    FROM groups
    WHERE groups.id = sqlc.arg(group_id) AND groups.space_id = sqlc.arg(space_id)
    UNION ALL
    SELECT child.id
    FROM groups child
    JOIN tree parent ON child.parent_id = parent.id
    WHERE child.space_id = sqlc.arg(space_id)
)
SELECT DISTINCT m.id, m.space_id, m.name, m.type, m.binding_policy, m.status, m.created_at
FROM members m
JOIN group_members gm ON gm.member_id = m.id
JOIN tree ON tree.id = gm.group_id
WHERE m.space_id = sqlc.arg(space_id)
  AND m.status <> 'removed'
ORDER BY m.id;

-- name: UpdateGroupParent :exec
UPDATE groups
SET parent_id = sqlc.narg(parent_id)
WHERE id = sqlc.arg(group_id) AND space_id = sqlc.arg(space_id);

-- name: LockMemberInSpace :one
SELECT id, space_id, name, type, binding_policy, status, created_at
FROM members
WHERE id = sqlc.arg(id) AND space_id = sqlc.arg(space_id)
FOR UPDATE;

-- name: SetMemberStatus :exec
UPDATE members SET status = sqlc.arg(status) WHERE id = sqlc.arg(id) AND space_id = sqlc.arg(space_id);

-- name: MemberApplicationIsActive :one
WITH RECURSIVE owners AS (
    SELECT m.id, m.type, m.source, m.oauth_client_id, m.home_group_id, ARRAY[m.id] AS path
    FROM members m WHERE m.id = sqlc.arg(member_id)
    UNION ALL
    SELECT m.id, m.type, m.source, m.oauth_client_id, m.home_group_id, child.path || m.id
    FROM owners child
    JOIN groups g ON g.id = child.home_group_id AND g.kind = 'agents'
    JOIN members m ON m.id = g.owner_member_id
    WHERE child.type = 'agent' AND cardinality(child.path) < 64 AND NOT (m.id = ANY(child.path))
)
SELECT EXISTS (SELECT 1 FROM owners) AND NOT EXISTS (
    SELECT 1 FROM owners m WHERE
        (m.type = 'agent' AND m.source = 'oauth' AND NOT EXISTS (
            SELECT 1 FROM applications a WHERE a.client_id = m.oauth_client_id
              AND a.status = 'active' AND (a.visibility = 'private' OR a.review_status = 'approved')
        ))
        OR (m.type = 'application' AND EXISTS (
            SELECT 1 FROM application_installations i JOIN applications a ON a.id = i.application_id
            WHERE i.member_id = m.id AND a.status <> 'active'
        ))
) AS active;

-- name: SetMemberBindingPolicy :exec
UPDATE members SET binding_policy = sqlc.arg(binding_policy) WHERE id = sqlc.arg(id) AND space_id = sqlc.arg(space_id);
