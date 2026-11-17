-- name: CreatePermission :one
INSERT INTO permissions (id, key, description) VALUES (sqlc.arg(id), sqlc.arg(key), sqlc.arg(description)) ON CONFLICT (key) DO UPDATE SET description=EXCLUDED.description RETURNING id, key, description, status, created_at;

-- name: CreateRole :one
INSERT INTO roles (id, space_id, name, description, managed) VALUES (sqlc.arg(id), sqlc.arg(space_id), sqlc.arg(name), sqlc.arg(description), sqlc.arg(managed)) RETURNING id, space_id, name, description, managed, created_at;

-- name: GrantRolePermission :exec
INSERT INTO role_permissions (role_id, permission_id) VALUES (sqlc.arg(role_id), sqlc.arg(permission_id)) ON CONFLICT DO NOTHING;

-- name: AssignRole :exec
INSERT INTO member_roles (member_id, role_id, granted_by) VALUES (sqlc.arg(member_id), sqlc.arg(role_id), sqlc.narg(granted_by)) ON CONFLICT DO NOTHING;

-- name: CreateGrant :one
INSERT INTO authorization_grants (id, space_id, role_id, permission_keys, grantee_member_id, scope, anchor_space_id, anchor_group_id, granted_by)
VALUES (sqlc.arg(id), sqlc.arg(space_id), sqlc.narg(role_id), sqlc.narg(permission_keys), sqlc.narg(grantee_member_id), sqlc.arg(scope), sqlc.narg(anchor_space_id), sqlc.narg(anchor_group_id), sqlc.arg(granted_by))
RETURNING id, space_id, role_id, permission_keys, grantee_member_id, grantee_group_id, scope, anchor_space_id, anchor_group_id, granted_by, created_at, revoked_at;

-- name: RevokeGrant :exec
UPDATE authorization_grants SET revoked_at = now()
WHERE id = sqlc.arg(id) AND revoked_at IS NULL;

-- name: CreateGroupGrant :one
INSERT INTO authorization_grants (id, space_id, role_id, permission_keys, grantee_group_id, scope, anchor_space_id, anchor_group_id, granted_by)
VALUES (sqlc.arg(id), sqlc.arg(space_id), sqlc.narg(role_id), sqlc.narg(permission_keys), sqlc.arg(grantee_group_id), sqlc.arg(scope), sqlc.narg(anchor_space_id), sqlc.narg(anchor_group_id), sqlc.arg(granted_by))
RETURNING id, space_id, role_id, permission_keys, grantee_member_id, grantee_group_id, scope, anchor_space_id, anchor_group_id, granted_by, created_at, revoked_at;

-- name: RevokeInlineGrantsForMember :exec
UPDATE authorization_grants SET revoked_at = now()
WHERE grantee_member_id = sqlc.arg(grantee_member_id)
  AND role_id IS NULL
  AND revoked_at IS NULL;

-- name: GetRoleInSpace :one
SELECT id, space_id, name, description, managed, created_at FROM roles
WHERE id = sqlc.arg(id) AND space_id = sqlc.arg(space_id);

-- name: LockRoleInSpace :one
SELECT id, space_id, name, description, managed, created_at FROM roles
WHERE id = sqlc.arg(id) AND space_id = sqlc.arg(space_id)
FOR UPDATE;

-- name: RoleIsApplicationInstallation :one
SELECT EXISTS (SELECT 1 FROM application_installations WHERE role_id = sqlc.arg(role_id));

-- name: ListActiveRoleGranteeMembers :many
WITH RECURSIVE role_grantee_groups AS (
    SELECT ag.grantee_group_id AS root_group_id, ag.grantee_group_id AS group_id
    FROM authorization_grants ag
    WHERE ag.role_id = sqlc.arg(role_id)
      AND ag.revoked_at IS NULL
      AND ag.grantee_group_id IS NOT NULL
    UNION ALL
    SELECT rgg.root_group_id, g.id
    FROM role_grantee_groups rgg
    JOIN groups g ON g.parent_id = rgg.group_id
), affected_members AS (
    SELECT ag.grantee_member_id AS member_id
    FROM authorization_grants ag
    WHERE ag.role_id = sqlc.arg(role_id)
      AND ag.revoked_at IS NULL
      AND ag.grantee_member_id IS NOT NULL
    UNION
    SELECT gm.member_id
    FROM authorization_grants ag
    JOIN role_grantee_groups rgg ON rgg.root_group_id = ag.grantee_group_id
    JOIN group_members gm ON gm.group_id = rgg.group_id
    WHERE ag.role_id = sqlc.arg(role_id)
      AND ag.revoked_at IS NULL
)
SELECT DISTINCT m.id AS member_id
FROM affected_members am
JOIN members m ON m.id = am.member_id
ORDER BY m.id;

-- name: ClearRolePermissions :exec
DELETE FROM role_permissions WHERE role_id = sqlc.arg(role_id);

-- name: UpdateRole :one
UPDATE roles
SET name = sqlc.arg(name), description = sqlc.arg(description)
WHERE id = sqlc.arg(id) AND space_id = sqlc.arg(space_id)
RETURNING id, space_id, name, description, managed, created_at;

-- name: ListRolesInSpace :many
SELECT id, space_id, name, description, managed, created_at FROM roles
WHERE space_id = sqlc.arg(space_id) ORDER BY name, id;

-- name: ListRolePermissions :many
SELECT p.key, p.status, p.delegable
FROM role_permissions rp
JOIN permissions p ON p.id = rp.permission_id
WHERE rp.role_id = sqlc.arg(role_id)
ORDER BY p.key;

-- name: ListMemberAssignments :many
WITH RECURSIVE member_groups AS (
    SELECT gm.group_id
    FROM group_members gm
    JOIN groups g ON g.id = gm.group_id AND g.status = 'active'
    WHERE gm.member_id = sqlc.arg(member_id)
    UNION
    SELECT g.parent_id
    FROM groups g
    JOIN member_groups mg ON mg.group_id = g.id
    WHERE g.parent_id IS NOT NULL AND g.status = 'active'
)
SELECT ag.id AS grant_id, ag.space_id, ag.role_id, COALESCE(r.name, 'inline') AS role_name,
       ag.scope, ag.anchor_space_id, ag.anchor_group_id, ag.grantee_member_id, ag.grantee_group_id,
       p.key AS permission_key, p.status, p.delegable, p.principal_kinds, p.agent_approval, s.policy_version
FROM authorization_grants ag
LEFT JOIN roles r ON r.id = ag.role_id
JOIN permissions p ON p.status <> 'disabled' AND (
    (ag.role_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM role_permissions rp
        WHERE rp.role_id = ag.role_id AND rp.permission_id = p.id
    ))
    OR (ag.permission_keys IS NOT NULL AND ag.permission_keys ? p.key)
)
JOIN spaces s ON s.id = ag.space_id
LEFT JOIN member_groups mg ON mg.group_id = ag.grantee_group_id
LEFT JOIN groups grant_group ON grant_group.id = ag.grantee_group_id
WHERE (ag.grantee_member_id = sqlc.arg(member_id) OR mg.group_id IS NOT NULL)
  AND (ag.grantee_group_id IS NULL OR grant_group.status = 'active')
  AND ag.revoked_at IS NULL
ORDER BY ag.id, p.key;

-- name: GetGrantInSpace :one
SELECT id, space_id, role_id, permission_keys, grantee_member_id, grantee_group_id, scope, anchor_space_id, anchor_group_id, granted_by, created_at, revoked_at
FROM authorization_grants
WHERE id = sqlc.arg(id) AND space_id = sqlc.arg(space_id);

-- name: GetGroupInSpace :one
SELECT id, space_id, name, parent_id, kind, owner_member_id, status, created_at
FROM groups
WHERE id = sqlc.arg(id) AND space_id = sqlc.arg(space_id);

-- name: GetGroupSpaceForAuthorization :one
SELECT space_id FROM groups WHERE id = sqlc.arg(id);

-- name: GetPermissionByKey :one
SELECT id, key, description, status, delegable, principal_kinds, agent_approval, created_at FROM permissions WHERE key=sqlc.arg(key);

-- name: GetSpaceEnvelopePermission :one
SELECT e.mode
FROM space_envelopes p
LEFT JOIN space_envelope_entries e
  ON e.space_id = p.space_id
 AND e.permission_id = (SELECT id FROM permissions WHERE key = sqlc.arg(permission_key))
WHERE p.space_id = sqlc.arg(space_id);

-- name: GetGroupEnvelopePermission :one
SELECT e.mode
FROM group_envelopes p
LEFT JOIN group_envelope_entries e
  ON e.group_id = p.group_id
 AND e.permission_id = (SELECT id FROM permissions WHERE key = sqlc.arg(permission_key))
WHERE p.group_id = sqlc.arg(group_id);
