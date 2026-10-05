-- name: CreateMember :one
INSERT INTO members (id, space_id, name, kind) VALUES (sqlc.arg(id), sqlc.arg(space_id), sqlc.arg(name), sqlc.arg(kind)) RETURNING id, space_id, name, kind, created_at;

-- name: CreateMemberWithPolicy :one
INSERT INTO members (id, space_id, name, kind, binding_policy)
VALUES (sqlc.arg(id), sqlc.arg(space_id), sqlc.arg(name), sqlc.arg(kind), sqlc.arg(binding_policy))
RETURNING id, space_id, name, kind, binding_policy, status, created_at;

-- name: LinkUserMember :exec
INSERT INTO user_members (user_id, member_id) VALUES (sqlc.arg(user_id), sqlc.arg(member_id)) ON CONFLICT DO NOTHING;

-- name: GetMemberForUser :one
SELECT m.id, m.space_id, m.name, m.kind, m.binding_policy, m.status, m.created_at FROM members m JOIN user_members um ON um.member_id=m.id WHERE um.user_id=sqlc.arg(user_id) AND um.status = 'active' AND (um.expires_at IS NULL OR um.expires_at > now()) AND um.revoked_at IS NULL AND m.status = 'active' AND m.space_id=sqlc.arg(space_id) LIMIT 1;

-- name: ListMembersInSpace :many
SELECT id, space_id, name, kind, binding_policy, status, created_at
FROM members WHERE space_id = sqlc.arg(space_id) AND status <> 'removed'
ORDER BY created_at, id;

-- name: GetMemberInSpace :one
SELECT id, space_id, name, kind, binding_policy, status, created_at
FROM members WHERE id = sqlc.arg(id) AND space_id = sqlc.arg(space_id);

-- name: ListMemberPermissions :many
SELECT m.id AS member_id, r.name AS role_name, p.key AS permission_key FROM members m JOIN member_roles mr ON mr.member_id=m.id JOIN roles r ON r.id=mr.role_id JOIN role_permissions rp ON rp.role_id=r.id JOIN permissions p ON p.id=rp.permission_id WHERE m.id=sqlc.arg(member_id);
