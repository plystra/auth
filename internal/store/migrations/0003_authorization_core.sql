-- +goose Up

ALTER TABLE members
    ADD COLUMN IF NOT EXISTS binding_policy text NOT NULL DEFAULT 'individual'
        CHECK (binding_policy IN ('individual', 'shared')),
    ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended', 'removed'));

ALTER TABLE user_members
    ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'revoked')),
    ADD COLUMN IF NOT EXISTS expires_at timestamptz,
    ADD COLUMN IF NOT EXISTS revoked_at timestamptz;

ALTER TABLE permissions
    ADD COLUMN IF NOT EXISTS enabled boolean NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS delegable boolean NOT NULL DEFAULT true;

ALTER TABLE api_keys
    ADD COLUMN IF NOT EXISTS allow_subject_assertion boolean NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS authorization_grants (
    id text PRIMARY KEY CHECK (id LIKE 'grt_%'),
    space_id text NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    role_id text NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    grantee_member_id text REFERENCES members(id) ON DELETE CASCADE,
    grantee_group_id text REFERENCES groups(id) ON DELETE CASCADE,
    scope text NOT NULL DEFAULT 'space' CHECK (scope IN ('self', 'group', 'group_tree', 'space', 'space_tree', 'global')),
    anchor_space_id text REFERENCES spaces(id) ON DELETE CASCADE,
    anchor_group_id text REFERENCES groups(id) ON DELETE CASCADE,
    granted_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    CHECK ((grantee_member_id IS NOT NULL) <> (grantee_group_id IS NOT NULL)),
    CHECK (scope NOT IN ('group', 'group_tree') OR anchor_group_id IS NOT NULL),
    CHECK (scope NOT IN ('space', 'space_tree') OR anchor_space_id IS NOT NULL),
    CHECK (scope <> 'global' OR (anchor_space_id IS NULL AND anchor_group_id IS NULL))
);
CREATE INDEX IF NOT EXISTS authorization_grants_member_idx
    ON authorization_grants(grantee_member_id, revoked_at)
    WHERE grantee_member_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS authorization_grants_group_idx
    ON authorization_grants(grantee_group_id, revoked_at)
    WHERE grantee_group_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS authorization_grants_active_unique
    ON authorization_grants(grantee_member_id, role_id, scope, COALESCE(anchor_space_id, ''), COALESCE(anchor_group_id, ''))
    WHERE revoked_at IS NULL AND grantee_member_id IS NOT NULL;

INSERT INTO permissions (id, key, description) VALUES
    ('prm_01h00000000000000000000001', 'self:read', 'Read the current authenticated identity'),
    ('prm_01h00000000000000000000002', 'auth.spaces:manage', 'Create and manage Spaces'),
    ('prm_01h00000000000000000000003', 'auth.members:read', 'Read Space members'),
    ('prm_01h00000000000000000000004', 'auth.members:manage', 'Create and manage Space members'),
    ('prm_01h00000000000000000000005', 'auth.roles:manage', 'Create and manage Space roles'),
    ('prm_01h00000000000000000000006', 'auth.grants:assign', 'Assign and revoke role grants'),
    ('prm_01h00000000000000000000007', 'auth.assign_rights:manage', 'Delegate assignment rights'),
    ('prm_01h00000000000000000000008', 'auth.envelopes:manage', 'Manage permission envelopes'),
    ('prm_01h00000000000000000000009', 'auth.audit:read', 'Read Space audit events'),
    ('prm_01h00000000000000000000010', 'auth.authz:check', 'Evaluate authorization decisions'),
    ('prm_01h00000000000000000000011', 'auth.tokens:introspect', 'Introspect authentication tokens')
ON CONFLICT (key) DO UPDATE SET description = EXCLUDED.description;

INSERT INTO roles (id, space_id, name, description, managed)
VALUES ('rol_01h00000000000000000000001', 'spc_01h00000000000000000000000', 'member', 'Default member role', true)
ON CONFLICT (space_id, name) DO NOTHING;

INSERT INTO roles (id, space_id, name, description, managed)
VALUES ('rol_01h00000000000000000000002', 'spc_01h00000000000000000000000', 'administrator', 'Default Space administrator role', true)
ON CONFLICT (space_id, name) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT 'rol_01h00000000000000000000001', id FROM permissions WHERE key = 'self:read'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT 'rol_01h00000000000000000000002', id FROM permissions
WHERE key IN ('self:read', 'auth.spaces:manage', 'auth.members:read', 'auth.members:manage', 'auth.roles:manage', 'auth.grants:assign', 'auth.assign_rights:manage', 'auth.envelopes:manage', 'auth.audit:read', 'auth.authz:check', 'auth.tokens:introspect')
ON CONFLICT DO NOTHING;

-- +goose Down
-- Forward-only migrations: add a compensating migration if rollback is required.
