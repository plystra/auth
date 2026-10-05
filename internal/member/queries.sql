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

-- name: ListMembersInSpace :many
SELECT id, space_id, name, type, binding_policy, status, created_at
FROM members WHERE space_id = sqlc.arg(space_id) AND status <> 'removed'
ORDER BY created_at, id;

-- name: GetMemberInSpace :one
SELECT id, space_id, name, type, binding_policy, status, created_at
FROM members WHERE id = sqlc.arg(id) AND space_id = sqlc.arg(space_id);

-- name: GetMemberForAuthorization :one
SELECT id, space_id, name, type, binding_policy, status, created_at
FROM members
WHERE id = sqlc.arg(id);

-- name: LockMemberInSpace :one
SELECT id, space_id, name, type, binding_policy, status, created_at
FROM members
WHERE id = sqlc.arg(id) AND space_id = sqlc.arg(space_id)
FOR UPDATE;

-- name: SetMemberStatus :exec
UPDATE members SET status = sqlc.arg(status) WHERE id = sqlc.arg(id) AND space_id = sqlc.arg(space_id);

-- name: SetMemberBindingPolicy :exec
UPDATE members SET binding_policy = sqlc.arg(binding_policy) WHERE id = sqlc.arg(id) AND space_id = sqlc.arg(space_id);
