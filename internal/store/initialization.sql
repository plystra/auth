-- name: EnsureDefaultSpace :exec
INSERT INTO spaces (id, name, slug)
VALUES ('spc_01h00000000000000000000000', 'Default Space', 'default')
ON CONFLICT (id) DO NOTHING;

-- name: EnsureDefaultApplication :exec
INSERT INTO applications (id, space_id, name, client_id, redirect_uris, allowed_scopes)
VALUES (
    'app_01h00000000000000000000000',
    'spc_01h00000000000000000000000',
    'Default Application',
    'default',
    '[]'::jsonb,
    '["auth.authz:check", "auth.tokens:introspect"]'::jsonb
)
ON CONFLICT (id) DO UPDATE
SET allowed_scopes = EXCLUDED.allowed_scopes
WHERE applications.allowed_scopes = '[]'::jsonb;

-- name: EnsureDefaultApplicationManifest :exec
UPDATE applications
SET manifest_permissions = '["auth.authz:check", "auth.tokens:introspect"]'::jsonb
WHERE id = 'app_01h00000000000000000000000'
  AND manifest_permissions = '[]'::jsonb;

-- name: EnsureDefaultApplicationMember :exec
INSERT INTO members (id, space_id, name, type, binding_policy)
SELECT 'mem_01h00000000000000000000040', space_id, 'Default Application', 'application', 'single'
FROM applications WHERE id = 'app_01h00000000000000000000000'
ON CONFLICT (id) DO NOTHING;

-- name: EnsureDefaultApplicationRole :exec
INSERT INTO roles (id, space_id, name, description, managed)
SELECT 'rol_01h00000000000000000000040', space_id, 'application:default', 'System-managed default application manifest', true
FROM applications WHERE id = 'app_01h00000000000000000000000'
ON CONFLICT (id) DO NOTHING;

-- name: EnsureDefaultApplicationRolePermissions :exec
INSERT INTO role_permissions (role_id, permission_id)
SELECT 'rol_01h00000000000000000000040', p.id
FROM permissions p JOIN roles r ON r.id = 'rol_01h00000000000000000000040'
WHERE p.key IN ('auth.authz:check', 'auth.tokens:introspect')
ON CONFLICT DO NOTHING;

-- name: EnsureDefaultApplicationGrant :exec
INSERT INTO authorization_grants (id, space_id, role_id, grantee_member_id, scope, anchor_space_id, granted_by)
SELECT 'grt_01h00000000000000000000040', app.space_id,
       'rol_01h00000000000000000000040', 'mem_01h00000000000000000000040',
       'space', app.space_id, 'system'
FROM applications app WHERE app.id = 'app_01h00000000000000000000000'
ON CONFLICT (id) DO NOTHING;

-- name: EnsureDefaultApplicationInstallation :exec
INSERT INTO application_installations (
    id, application_id, space_id, member_id, role_id, scope, approved_permissions, installed_by
)
SELECT 'ins_01h00000000000000000000040', app.id, app.space_id,
       'mem_01h00000000000000000000040', 'rol_01h00000000000000000000040',
       'space', app.manifest_permissions, NULL
FROM applications app WHERE app.id = 'app_01h00000000000000000000000'
ON CONFLICT (id) DO NOTHING;

-- name: CountAPIKeysForApplication :one
SELECT count(*)::bigint
FROM api_keys
WHERE application_id = sqlc.arg(application_id);
