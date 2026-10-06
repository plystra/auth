-- +goose Up

-- Keep the built-in governance catalog in lockstep with authorization-model.md.
-- These rows are upserted so the migration is safe for installations that
-- already received the older, incomplete seed catalog.
INSERT INTO permissions (id, key, description, delegable, principal_kinds, agent_approval, risk)
VALUES
    ('prm_01h00000000000000000000002', 'auth.spaces:manage', 'Create, suspend and manage descendant Spaces', true, '["human","agent"]'::jsonb, 'none', 'critical'),
    ('prm_01h00000000000000000000003', 'auth.members:read', 'Read members, groups and installed applications', true, '["human","agent","application"]'::jsonb, 'none', 'low'),
    ('prm_01h00000000000000000000004', 'auth.members:manage', 'Invite, create, suspend and remove Space members', true, '["human","agent","application"]'::jsonb, 'none', 'high'),
    ('prm_01h00000000000000000000005', 'auth.roles:manage', 'Define roles on Spaces and groups', true, '["human","agent"]'::jsonb, 'none', 'high'),
    ('prm_01h00000000000000000000006', 'auth.grants:assign', 'Assign and revoke roles and inline permissions', true, '["human","agent","application"]'::jsonb, 'none', 'high'),
    ('prm_01h00000000000000000000007', 'auth.assign_rights:manage', 'Delegate assignment rights to administrators', true, '["human","agent"]'::jsonb, 'none', 'critical'),
    ('prm_01h00000000000000000000008', 'auth.envelopes:manage', 'Narrow permission envelopes on descendant nodes', true, '["human","agent"]'::jsonb, 'none', 'critical'),
    ('prm_01h00000000000000000000009', 'auth.audit:read', 'Read audit events in the authorized scope', true, '["human","agent"]'::jsonb, 'none', 'high'),
    ('prm_01h00000000000000000000010', 'auth.authz:check', 'Evaluate authorization decisions', true, '["application"]'::jsonb, 'none', 'low'),
    ('prm_01h00000000000000000000011', 'auth.tokens:introspect', 'Introspect access tokens and Agent keys', true, '["application"]'::jsonb, 'none', 'high'),
    ('prm_01h00000000000000000000012', 'auth.bindings:manage', 'Bind users to members and manage binding policy', true, '["human","agent"]'::jsonb, 'required', 'critical'),
    ('prm_01h00000000000000000000013', 'auth.agents:create', 'Create and manage Agent members', true, '["human","agent","application"]'::jsonb, 'none', 'high'),
    ('prm_01h00000000000000000000014', 'auth.groups:manage', 'Create, move, suspend groups and manage group members', true, '["human","agent","application"]'::jsonb, 'none', 'high'),
    ('prm_01h00000000000000000000015', 'auth.applications:manage', 'Register applications, manage keys and install applications', true, '["human","agent"]'::jsonb, 'none', 'critical'),
    ('prm_01h00000000000000000000016', 'auth.connections:manage', 'Manage SSO, directory, domains, audit streams and IT portals', true, '["human","agent"]'::jsonb, 'required', 'critical'),
    ('prm_01h00000000000000000000017', 'auth.audit:write', 'Write business audit events', true, '["application"]'::jsonb, 'none', 'low'),
    ('prm_01h00000000000000000000018', 'auth.authz:explain', 'Explain and simulate authorization decisions', true, '["application"]'::jsonb, 'none', 'high'),
    ('prm_01h00000000000000000000019', 'auth.users:manage', 'Manage user accounts globally', true, '["application"]'::jsonb, 'none', 'critical'),
    ('prm_01h00000000000000000000020', 'auth.users:impersonate', 'Issue an impersonated user session', false, '["human"]'::jsonb, 'none', 'critical'),
    ('prm_01h00000000000000000000021', 'auth.envelopes:apply', 'Apply a registered envelope template globally', false, '["application"]'::jsonb, 'none', 'critical')
ON CONFLICT (key) DO UPDATE SET
    description = EXCLUDED.description,
    delegable = EXCLUDED.delegable,
    principal_kinds = EXCLUDED.principal_kinds,
    agent_approval = EXCLUDED.agent_approval,
    risk = EXCLUDED.risk;

-- +goose Down
-- Forward-only migration: replace this migration with a compensating migration.
