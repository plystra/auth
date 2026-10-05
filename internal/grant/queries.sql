-- name: CreatePermission :one
INSERT INTO permissions (id, key, description) VALUES (sqlc.arg(id), sqlc.arg(key), sqlc.arg(description)) ON CONFLICT (key) DO UPDATE SET description=EXCLUDED.description RETURNING id, key, description, created_at;

-- name: CreateRole :one
INSERT INTO roles (id, space_id, name, description, managed) VALUES (sqlc.arg(id), sqlc.arg(space_id), sqlc.arg(name), sqlc.arg(description), sqlc.arg(managed)) RETURNING id, space_id, name, description, managed, created_at;

-- name: GrantRolePermission :exec
INSERT INTO role_permissions (role_id, permission_id) VALUES (sqlc.arg(role_id), sqlc.arg(permission_id)) ON CONFLICT DO NOTHING;

-- name: AssignRole :exec
INSERT INTO member_roles (member_id, role_id, granted_by) VALUES (sqlc.arg(member_id), sqlc.arg(role_id), sqlc.narg(granted_by)) ON CONFLICT DO NOTHING;

-- name: CreateGrant :one
INSERT INTO authorization_grants (id, space_id, role_id, grantee_member_id, scope, anchor_space_id, granted_by)
VALUES (sqlc.arg(id), sqlc.arg(space_id), sqlc.arg(role_id), sqlc.arg(grantee_member_id), sqlc.arg(scope), sqlc.narg(anchor_space_id), sqlc.arg(granted_by))
RETURNING id, space_id, role_id, grantee_member_id, grantee_group_id, scope, anchor_space_id, anchor_group_id, granted_by, created_at, revoked_at;

-- name: RevokeGrant :exec
UPDATE authorization_grants SET revoked_at = now()
WHERE id = sqlc.arg(id) AND revoked_at IS NULL;

-- name: GetRoleInSpace :one
SELECT id, space_id, name, description, managed, created_at FROM roles
WHERE id = sqlc.arg(id) AND space_id = sqlc.arg(space_id);

-- name: ListRolesInSpace :many
SELECT id, space_id, name, description, managed, created_at FROM roles
WHERE space_id = sqlc.arg(space_id) ORDER BY name, id;

-- name: ListRolePermissions :many
SELECT p.key, p.enabled, p.delegable
FROM role_permissions rp
JOIN permissions p ON p.id = rp.permission_id
WHERE rp.role_id = sqlc.arg(role_id)
ORDER BY p.key;

-- name: ListMemberAssignments :many
SELECT g.id AS grant_id, g.space_id, g.role_id, r.name AS role_name,
       g.scope, g.anchor_space_id, g.grantee_member_id,
       p.key AS permission_key, p.enabled, p.delegable, p.principal_kinds, p.agent_approval, s.policy_version
FROM authorization_grants g
JOIN roles r ON r.id = g.role_id
JOIN role_permissions rp ON rp.role_id = r.id
JOIN permissions p ON p.id = rp.permission_id
JOIN spaces s ON s.id = g.space_id
WHERE g.grantee_member_id = sqlc.arg(member_id)
  AND g.revoked_at IS NULL
  AND p.enabled = true
ORDER BY g.id, p.key;

-- name: GetGrantInSpace :one
SELECT id, space_id, role_id, grantee_member_id, grantee_group_id, scope, anchor_space_id, anchor_group_id, granted_by, created_at, revoked_at
FROM authorization_grants
WHERE id = sqlc.arg(id) AND space_id = sqlc.arg(space_id);

-- name: GetPermissionByKey :one
SELECT id, key, description, created_at FROM permissions WHERE key=sqlc.arg(key);
