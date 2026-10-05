-- name: CreatePermission :one
INSERT INTO permissions (id, key, description) VALUES (sqlc.arg(id), sqlc.arg(key), sqlc.arg(description)) ON CONFLICT (key) DO UPDATE SET description=EXCLUDED.description RETURNING id, key, description, created_at;

-- name: CreateRole :one
INSERT INTO roles (id, space_id, name, description, managed) VALUES (sqlc.arg(id), sqlc.arg(space_id), sqlc.arg(name), sqlc.arg(description), sqlc.arg(managed)) RETURNING id, space_id, name, description, managed, created_at;

-- name: GrantRolePermission :exec
INSERT INTO role_permissions (role_id, permission_id) VALUES (sqlc.arg(role_id), sqlc.arg(permission_id)) ON CONFLICT DO NOTHING;

-- name: AssignRole :exec
INSERT INTO member_roles (member_id, role_id, granted_by) VALUES (sqlc.arg(member_id), sqlc.arg(role_id), sqlc.narg(granted_by)) ON CONFLICT DO NOTHING;

-- name: GetPermissionByKey :one
SELECT id, key, description, created_at FROM permissions WHERE key=sqlc.arg(key);
