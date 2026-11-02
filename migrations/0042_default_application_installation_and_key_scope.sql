-- +goose Up

-- A bootstrap installation has no human installer. Existing keys retain their
-- original publisher-Space boundary when installation-aware checks begin.
ALTER TABLE application_installations ALTER COLUMN installed_by DROP NOT NULL;

ALTER TABLE api_keys
    ADD COLUMN restrict_to jsonb NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(restrict_to) = 'array');

UPDATE api_keys AS key
SET restrict_to = jsonb_build_array(jsonb_build_object(
    'space_id', app.space_id, 'include_descendants', false
))
FROM applications AS app
WHERE app.id = key.application_id;

UPDATE applications
SET manifest_permissions = '["auth.authz:check", "auth.tokens:introspect"]'::jsonb
WHERE id = 'app_01h00000000000000000000000'
  AND manifest_permissions = '[]'::jsonb;

INSERT INTO members (id, space_id, name, type, binding_policy)
SELECT 'mem_01h00000000000000000000040', space_id, 'Default Application', 'application', 'single'
FROM applications WHERE id = 'app_01h00000000000000000000000'
ON CONFLICT (id) DO NOTHING;

INSERT INTO roles (id, space_id, name, description, managed)
SELECT 'rol_01h00000000000000000000040', space_id, 'application:default', 'System-managed default application manifest', true
FROM applications WHERE id = 'app_01h00000000000000000000000'
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT 'rol_01h00000000000000000000040', p.id
FROM permissions p JOIN roles r ON r.id = 'rol_01h00000000000000000000040'
WHERE p.key IN ('auth.authz:check', 'auth.tokens:introspect')
ON CONFLICT DO NOTHING;

INSERT INTO authorization_grants (id, space_id, role_id, grantee_member_id, scope, anchor_space_id, granted_by)
SELECT 'grt_01h00000000000000000000040', app.space_id,
       'rol_01h00000000000000000000040', 'mem_01h00000000000000000000040',
       'space', app.space_id, 'system'
FROM applications AS app WHERE app.id = 'app_01h00000000000000000000000'
ON CONFLICT (id) DO NOTHING;

INSERT INTO application_installations (
    id, application_id, space_id, member_id, role_id, scope, approved_permissions, installed_by
)
SELECT 'ins_01h00000000000000000000040', app.id, app.space_id,
       'mem_01h00000000000000000000040', 'rol_01h00000000000000000000040',
       'space', app.manifest_permissions, NULL
FROM applications AS app WHERE app.id = 'app_01h00000000000000000000000'
ON CONFLICT (id) DO NOTHING;

-- +goose Down
-- Forward-only migrations: add a compensating migration if rollback is required.
