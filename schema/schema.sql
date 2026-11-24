
CREATE TABLE instance_settings (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    registration_mode text NOT NULL DEFAULT 'closed' CHECK (registration_mode IN ('open','closed','invite_only')),
    require_email_verification boolean NOT NULL DEFAULT true,
    allowed_origins jsonb NOT NULL DEFAULT '[]'::jsonb,
    password_min_length integer NOT NULL DEFAULT 12 CHECK (password_min_length BETWEEN 8 AND 128),
    access_token_ttl_seconds integer NOT NULL DEFAULT 60 CHECK (access_token_ttl_seconds BETWEEN 30 AND 300),
    refresh_token_ttl_seconds integer NOT NULL DEFAULT 2592000 CHECK (refresh_token_ttl_seconds BETWEEN 3600 AND 31536000),
    refresh_idle_ttl_seconds integer NOT NULL DEFAULT 1209600 CHECK (refresh_idle_ttl_seconds BETWEEN 900 AND 31536000),
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by text
);
INSERT INTO instance_settings (id) VALUES (true) ON CONFLICT DO NOTHING;

CREATE TABLE users (
    id text PRIMARY KEY CHECK (id LIKE 'usr_%'),
    email text NOT NULL,
    email_normalized text NOT NULL UNIQUE,
    password_hash text NOT NULL,
    email_verified_at timestamptz,
    disabled_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX users_email_idx ON users (email_normalized);

CREATE TABLE sessions (
    id text PRIMARY KEY CHECK (id LIKE 'ses_%'),
    user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    ip text,
    user_agent text,
    auth_time timestamptz NOT NULL DEFAULT now(),
    assurance_level smallint NOT NULL DEFAULT 1 CHECK (assurance_level BETWEEN 1 AND 3)
);
CREATE INDEX sessions_user_idx ON sessions(user_id);
CREATE INDEX sessions_active_idx ON sessions(user_id, expires_at) WHERE revoked_at IS NULL;

CREATE TABLE refresh_tokens (
    id text PRIMARY KEY CHECK (id LIKE 'rft_%'),
    session_id text NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    family_id text NOT NULL CHECK (family_id LIKE 'rtf_%'),
    token_hash bytea NOT NULL UNIQUE,
    issued_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    revoked_at timestamptz
);
CREATE INDEX refresh_family_idx ON refresh_tokens(family_id);

CREATE TABLE email_verification_tokens (
    id text PRIMARY KEY CHECK (id LIKE 'evt_%'),
    user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz
);

CREATE TABLE password_reset_tokens (
    id text PRIMARY KEY CHECK (id LIKE 'prt_%'),
    user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz
);

CREATE TABLE factors (
    id text PRIMARY KEY CHECK (id LIKE 'fac_%'),
    user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('totp','webauthn','backup_code')),
    name text NOT NULL,
    secret_ciphertext bytea,
    credential_id bytea,
    public_key bytea,
    counter bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    UNIQUE(user_id, name)
);

CREATE TABLE spaces (
    id text PRIMARY KEY CHECK (id LIKE 'spc_%'),
    name text NOT NULL,
    slug text NOT NULL UNIQUE,
    parent_id text REFERENCES spaces(id),
    policy_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX spaces_parent_idx ON spaces(parent_id);

CREATE TABLE groups (
    id text PRIMARY KEY CHECK (id LIKE 'grp_%'),
    space_id text NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    name text NOT NULL,
    parent_id text REFERENCES groups(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(space_id, name)
);

CREATE TABLE members (
    id text PRIMARY KEY CHECK (id LIKE 'mem_%'),
    space_id text NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    name text NOT NULL,
    kind text NOT NULL DEFAULT 'user' CHECK (kind IN ('user','service','agent')),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE user_members (
    user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    member_id text NOT NULL REFERENCES members(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(user_id, member_id)
);
CREATE INDEX user_members_member_idx ON user_members(member_id);
CREATE TABLE group_members (
    group_id text NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    member_id text NOT NULL REFERENCES members(id) ON DELETE CASCADE,
    PRIMARY KEY(group_id, member_id)
);

CREATE TABLE permissions (
    id text PRIMARY KEY CHECK (id LIKE 'prm_%'),
    key text NOT NULL UNIQUE,
    description text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE roles (
    id text PRIMARY KEY CHECK (id LIKE 'rol_%'),
    space_id text NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    name text NOT NULL,
    description text NOT NULL DEFAULT '',
    managed boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(space_id, name)
);
CREATE TABLE role_permissions (
    role_id text NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id text NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY(role_id, permission_id)
);
CREATE TABLE member_roles (
    member_id text NOT NULL REFERENCES members(id) ON DELETE CASCADE,
    role_id text NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    granted_by text,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(member_id, role_id)
);

CREATE TABLE applications (
    id text PRIMARY KEY CHECK (id LIKE 'app_%'),
    space_id text NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    name text NOT NULL,
    redirect_uris jsonb NOT NULL DEFAULT '[]'::jsonb,
    allowed_scopes jsonb NOT NULL DEFAULT '[]'::jsonb,
    client_id text NOT NULL UNIQUE,
    client_secret_hash bytea,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE api_keys (
    id text PRIMARY KEY CHECK (id LIKE 'key_%'),
    application_id text NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    name text NOT NULL,
    prefix text NOT NULL UNIQUE,
    secret_hash bytea NOT NULL,
    scopes jsonb NOT NULL DEFAULT '[]'::jsonb,
    expires_at timestamptz,
    last_used_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX api_keys_active_idx ON api_keys(prefix) WHERE revoked_at IS NULL;

CREATE TABLE operators (
    user_id text PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    capabilities jsonb NOT NULL DEFAULT '[]'::jsonb,
    active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_step_up_at timestamptz
);
CREATE TABLE agents (
    id text PRIMARY KEY CHECK (id LIKE 'agt_%'),
    space_id text NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    name text NOT NULL,
    owner_member_id text REFERENCES members(id),
    created_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO spaces (id, name, slug) VALUES ('spc_01h00000000000000000000000', 'Default Space', 'default') ON CONFLICT DO NOTHING;
INSERT INTO applications (id, space_id, name, client_id, redirect_uris, allowed_scopes) VALUES ('app_01h00000000000000000000000', 'spc_01h00000000000000000000000', 'Default Application', 'default', '[]'::jsonb, '[]'::jsonb) ON CONFLICT DO NOTHING;
CREATE TABLE authorization_codes (
    id text PRIMARY KEY CHECK (id LIKE 'cod_%'),
    application_id text NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri text NOT NULL,
    code_challenge text,
    code_challenge_method text,
    scope text NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz
);

CREATE TABLE audit_logs (
    id text PRIMARY KEY CHECK (id LIKE 'aud_%'),
    occurred_at timestamptz NOT NULL DEFAULT now(),
    actor_type text NOT NULL,
    actor_id text,
    action text NOT NULL,
    resource_type text,
    resource_id text,
    outcome text NOT NULL CHECK (outcome IN ('allow','deny','success','failure')),
    request_id text,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_logs_time_idx ON audit_logs(occurred_at DESC);
CREATE INDEX audit_logs_actor_idx ON audit_logs(actor_id, occurred_at DESC);

CREATE TABLE rate_limit_buckets (
    bucket_key text NOT NULL,
    window_start timestamptz NOT NULL,
    count integer NOT NULL DEFAULT 0,
    PRIMARY KEY(bucket_key, window_start)
);

CREATE TABLE outbox_events (
    id text PRIMARY KEY CHECK (id LIKE 'evt_%'),
    topic text NOT NULL,
    payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    delivered_at timestamptz
);
CREATE INDEX outbox_pending_idx ON outbox_events(created_at) WHERE delivered_at IS NULL;

CREATE FUNCTION reject_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'audit_logs is append-only'; END;
$$;
CREATE TRIGGER audit_logs_no_update BEFORE UPDATE OR DELETE ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_audit_mutation();


CREATE TABLE operator_sessions (
    id text PRIMARY KEY CHECK (id ~ '^ops_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    user_id text NOT NULL REFERENCES operators(user_id) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    idle_expires_at timestamptz NOT NULL,
    access_expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    assurance_level smallint NOT NULL DEFAULT 1 CHECK (assurance_level BETWEEN 1 AND 3),
    step_up_operation text,
    step_up_digest bytea,
    step_up_expires_at timestamptz,
    ip text,
    user_agent text
);
CREATE INDEX operator_sessions_active_idx ON operator_sessions(user_id, expires_at) WHERE revoked_at IS NULL;


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


ALTER TABLE users
    ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'active'
        CHECK (status IN ('pending', 'active', 'suspended', 'disabled'));

UPDATE users SET status = 'disabled' WHERE disabled_at IS NOT NULL AND status = 'active';

INSERT INTO permissions (id, key, description)
VALUES ('prm_01h00000000000000000000012', 'auth.bindings:manage', 'Bind and revoke users on members')
ON CONFLICT (key) DO UPDATE SET description = EXCLUDED.description;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'administrator' AND p.key = 'auth.bindings:manage'
ON CONFLICT DO NOTHING;


-- Agent-first authorization: agents are members with an immutable owner group.
-- Keep the legacy kind column during the migration window; type is the
-- canonical value used by new code and is intentionally never client supplied
-- for agent creation.
ALTER TABLE members ADD COLUMN IF NOT EXISTS type text;
UPDATE members
SET type = CASE kind
    WHEN 'user' THEN 'human'
    WHEN 'service' THEN 'application'
    ELSE kind
END
WHERE type IS NULL;
ALTER TABLE members ALTER COLUMN type SET DEFAULT 'human';
ALTER TABLE members ALTER COLUMN type SET NOT NULL;
ALTER TABLE members DROP CONSTRAINT IF EXISTS members_type_check;
ALTER TABLE members ADD CONSTRAINT members_type_check CHECK (type IN ('human', 'agent', 'application'));
ALTER TABLE members ADD COLUMN IF NOT EXISTS version bigint NOT NULL DEFAULT 1;
ALTER TABLE members ADD COLUMN IF NOT EXISTS metadata jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE members ADD COLUMN IF NOT EXISTS home_group_id text REFERENCES groups(id);
ALTER TABLE members ADD COLUMN IF NOT EXISTS created_by_user_id text REFERENCES users(id);
ALTER TABLE members ADD COLUMN IF NOT EXISTS created_by_member_id text REFERENCES members(id);
ALTER TABLE members ADD COLUMN IF NOT EXISTS source text;
ALTER TABLE members ADD COLUMN IF NOT EXISTS oauth_client_id text;
ALTER TABLE members ADD COLUMN IF NOT EXISTS expires_at timestamptz;
ALTER TABLE members ADD COLUMN IF NOT EXISTS deleted_at timestamptz;
ALTER TABLE members ADD CONSTRAINT members_agent_fields_check CHECK (
    (type = 'agent' AND home_group_id IS NOT NULL AND binding_policy = 'individual' AND created_by_member_id IS NOT NULL)
    OR (type <> 'agent' AND home_group_id IS NULL)
);
CREATE INDEX IF NOT EXISTS members_type_idx ON members(space_id, type, status);

ALTER TABLE groups ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'standard';
ALTER TABLE groups DROP CONSTRAINT IF EXISTS groups_kind_check;
ALTER TABLE groups ADD CONSTRAINT groups_kind_check CHECK (kind IN ('standard', 'agents'));
ALTER TABLE groups ADD COLUMN IF NOT EXISTS owner_member_id text REFERENCES members(id);
ALTER TABLE groups ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'active';
ALTER TABLE groups ADD CONSTRAINT groups_status_check CHECK (status IN ('active', 'suspended', 'removed'));
CREATE UNIQUE INDEX IF NOT EXISTS groups_agents_owner_unique
    ON groups(owner_member_id) WHERE kind = 'agents' AND status <> 'removed';
CREATE INDEX IF NOT EXISTS groups_owner_idx ON groups(owner_member_id) WHERE owner_member_id IS NOT NULL;

ALTER TABLE group_members ADD COLUMN IF NOT EXISTS source text NOT NULL DEFAULT 'manual';
ALTER TABLE group_members DROP CONSTRAINT IF EXISTS group_members_source_check;
ALTER TABLE group_members ADD CONSTRAINT group_members_source_check CHECK (source IN ('manual', 'directory', 'system'));

CREATE TABLE IF NOT EXISTS agent_credentials (
    id text PRIMARY KEY CHECK (id LIKE 'crd_%'),
    member_id text NOT NULL REFERENCES members(id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('key', 'oauth_refresh')),
    prefix text NOT NULL UNIQUE,
    secret_hash bytea NOT NULL UNIQUE,
    family_id text,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    last_used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS agent_credentials_active_idx
    ON agent_credentials(prefix) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS agent_credentials_member_idx
    ON agent_credentials(member_id, revoked_at);

ALTER TABLE permissions ADD COLUMN IF NOT EXISTS risk text NOT NULL DEFAULT 'low';
ALTER TABLE permissions ADD COLUMN IF NOT EXISTS principal_kinds jsonb NOT NULL DEFAULT '["human","agent","application"]'::jsonb;
ALTER TABLE permissions ADD COLUMN IF NOT EXISTS agent_approval text NOT NULL DEFAULT 'none';
ALTER TABLE permissions ADD CONSTRAINT permissions_risk_check CHECK (risk IN ('low', 'high', 'critical'));
ALTER TABLE permissions ADD CONSTRAINT permissions_agent_approval_check CHECK (agent_approval IN ('none', 'required'));

INSERT INTO permissions (id, key, description, principal_kinds, agent_approval, risk)
VALUES ('prm_01h00000000000000000000013', 'auth.agents:create', 'Create and manage Agent members', '["human","agent","application"]'::jsonb, 'none', 'high')
ON CONFLICT (key) DO UPDATE SET description = EXCLUDED.description,
    principal_kinds = EXCLUDED.principal_kinds, agent_approval = EXCLUDED.agent_approval, risk = EXCLUDED.risk;
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'administrator' AND p.key = 'auth.agents:create'
ON CONFLICT DO NOTHING;

-- Existing records are human members. The legacy kind remains a compatibility
-- mirror until all clients consume members.type.
UPDATE members SET type = 'human' WHERE type = 'user';


ALTER TABLE members DROP CONSTRAINT IF EXISTS members_binding_policy_check;
ALTER TABLE members DROP CONSTRAINT IF EXISTS members_agent_fields_check;
UPDATE members SET binding_policy = 'single' WHERE binding_policy = 'individual';
ALTER TABLE members ALTER COLUMN binding_policy SET DEFAULT 'single';
ALTER TABLE members ADD CONSTRAINT members_binding_policy_check CHECK (binding_policy IN ('single', 'shared'));
ALTER TABLE members ADD CONSTRAINT members_agent_fields_check CHECK (
    (type = 'agent' AND home_group_id IS NOT NULL AND binding_policy = 'single' AND created_by_member_id IS NOT NULL)
    OR (type <> 'agent' AND home_group_id IS NULL)
);


-- A grant may carry a named role or an inline permission set. Inline grants
-- are used for short lived consent (for example OAuth Agent authorization)
-- without polluting the Space role catalog.
ALTER TABLE authorization_grants
    ALTER COLUMN role_id DROP NOT NULL,
    ADD COLUMN IF NOT EXISTS permission_keys jsonb;

ALTER TABLE authorization_grants
    DROP CONSTRAINT IF EXISTS authorization_grants_source_check;
ALTER TABLE authorization_grants
    ADD CONSTRAINT authorization_grants_source_check CHECK (
        (role_id IS NOT NULL AND permission_keys IS NULL)
        OR (role_id IS NULL AND jsonb_typeof(permission_keys) = 'array' AND jsonb_array_length(permission_keys) > 0)
    );

-- Inline grants are independently revocable and must not collide with role
-- grants that happen to cover the same permission set.
CREATE INDEX IF NOT EXISTS authorization_grants_inline_idx
    ON authorization_grants USING gin (permission_keys)
    WHERE permission_keys IS NOT NULL AND revoked_at IS NULL;


ALTER TABLE permissions
    ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'active';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'permissions_status_check'
          AND conrelid = 'permissions'::regclass
    ) THEN
        ALTER TABLE permissions
            ADD CONSTRAINT permissions_status_check
            CHECK (status IN ('active', 'deprecated', 'disabled'));
    END IF;
END $$;

UPDATE permissions
SET status = CASE WHEN enabled THEN 'active' ELSE 'disabled' END
WHERE status = 'active' AND enabled = false;

ALTER TABLE permissions DROP COLUMN IF EXISTS enabled;


ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS member_id text REFERENCES members(id);

CREATE INDEX IF NOT EXISTS sessions_member_idx ON sessions(member_id);


-- An absent policy inherits its parent. A present policy lists the complete
-- local ceiling; omitted permissions are excluded at this node.
CREATE TABLE space_envelopes (
    space_id text PRIMARY KEY REFERENCES spaces(id)
);

CREATE TABLE space_envelope_entries (
    space_id text NOT NULL REFERENCES space_envelopes(space_id),
    permission_id text NOT NULL REFERENCES permissions(id),
    mode text NOT NULL CHECK (mode IN ('use', 'assign', 'delegate')),
    PRIMARY KEY (space_id, permission_id)
);

CREATE TABLE group_envelopes (
    group_id text PRIMARY KEY REFERENCES groups(id)
);

CREATE TABLE group_envelope_entries (
    group_id text NOT NULL REFERENCES group_envelopes(group_id),
    permission_id text NOT NULL REFERENCES permissions(id),
    mode text NOT NULL CHECK (mode IN ('use', 'assign', 'delegate')),
    PRIMARY KEY (group_id, permission_id)
);


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


CREATE TABLE idempotency_keys (
    id text PRIMARY KEY CHECK (id LIKE 'idk_%'),
    scope_hash text NOT NULL,
    method text NOT NULL,
    path text NOT NULL,
    idempotency_key text NOT NULL,
    request_hash bytea NOT NULL,
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'completed')),
    status_code integer,
    response_headers jsonb NOT NULL DEFAULT '{}'::jsonb,
    response_body bytea,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    UNIQUE (scope_hash, method, path, idempotency_key)
);

CREATE INDEX idempotency_keys_expiry_idx ON idempotency_keys (expires_at);


ALTER TABLE spaces
    ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'active';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'spaces_status_check'
          AND conrelid = 'spaces'::regclass
    ) THEN
        ALTER TABLE spaces
            ADD CONSTRAINT spaces_status_check
            CHECK (status IN ('active', 'suspended'));
    END IF;
END $$;


DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM group_members gm
        JOIN groups g ON g.id = gm.group_id
        JOIN members m ON m.id = gm.member_id
        WHERE g.space_id <> m.space_id
    ) THEN
        RAISE EXCEPTION 'group_members contains cross-Space memberships; repair them before migrating';
    END IF;
    IF EXISTS (
        SELECT 1 FROM groups child
        JOIN groups parent ON parent.id = child.parent_id
        WHERE child.space_id <> parent.space_id
    ) THEN
        RAISE EXCEPTION 'groups contains cross-Space parent links; repair them before migrating';
    END IF;
END $$;

ALTER TABLE groups ADD CONSTRAINT groups_id_space_unique UNIQUE (id, space_id);
ALTER TABLE members ADD CONSTRAINT members_id_space_unique UNIQUE (id, space_id);

ALTER TABLE group_members ADD COLUMN space_id text;
UPDATE group_members gm SET space_id = g.space_id FROM groups g WHERE gm.group_id = g.id;
ALTER TABLE group_members ALTER COLUMN space_id SET NOT NULL;

ALTER TABLE group_members ADD CONSTRAINT group_members_group_space_fk
    FOREIGN KEY (group_id, space_id) REFERENCES groups (id, space_id) ON DELETE CASCADE;
ALTER TABLE group_members ADD CONSTRAINT group_members_member_space_fk
    FOREIGN KEY (member_id, space_id) REFERENCES members (id, space_id) ON DELETE CASCADE;
ALTER TABLE groups ADD CONSTRAINT groups_parent_space_fk
    FOREIGN KEY (parent_id, space_id) REFERENCES groups (id, space_id);

CREATE FUNCTION set_group_member_space() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    group_space text;
BEGIN
    SELECT g.space_id INTO group_space FROM groups g WHERE g.id = NEW.group_id;
    IF group_space IS NULL THEN
        RAISE EXCEPTION 'group % does not exist', NEW.group_id USING ERRCODE = '23503';
    END IF;
    IF NEW.space_id IS NOT NULL AND NEW.space_id <> group_space THEN
        RAISE EXCEPTION 'group membership Space does not match its group' USING ERRCODE = '23514';
    END IF;
    NEW.space_id := group_space;
    RETURN NEW;
END;
$$;

CREATE TRIGGER group_members_set_space
    BEFORE INSERT OR UPDATE OF group_id, space_id ON group_members
    FOR EACH ROW EXECUTE FUNCTION set_group_member_space();


CREATE TABLE assign_rights (
    id text PRIMARY KEY CHECK (left(id, 3) = 'ar_'),
    holder_member_id text NOT NULL REFERENCES members(id) ON DELETE CASCADE,
    permission_keys jsonb NOT NULL
        CHECK (CASE WHEN jsonb_typeof(permission_keys) = 'array'
            THEN jsonb_array_length(permission_keys) > 0 ELSE false END),
    anchor_space_id text REFERENCES spaces(id) ON DELETE CASCADE,
    anchor_group_id text REFERENCES groups(id) ON DELETE CASCADE,
    covers_subtree boolean NOT NULL DEFAULT false,
    can_redelegate boolean NOT NULL DEFAULT false,
    source text NOT NULL CHECK (source IN ('system', 'operator', 'delegated')),
    parent_id text REFERENCES assign_rights(id),
    granted_by_operator_user_id text REFERENCES operators(user_id),
    expires_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((anchor_space_id IS NOT NULL) <> (anchor_group_id IS NOT NULL)),
    CHECK (parent_id IS DISTINCT FROM id),
    CHECK (expires_at IS NULL OR expires_at > created_at),
    CHECK (
        (source = 'system' AND parent_id IS NULL AND granted_by_operator_user_id IS NULL)
        OR (source = 'operator' AND parent_id IS NULL AND granted_by_operator_user_id IS NOT NULL)
        OR (source = 'delegated' AND parent_id IS NOT NULL AND granted_by_operator_user_id IS NULL)
    )
);

CREATE INDEX assign_rights_holder_active_idx
    ON assign_rights(holder_member_id, expires_at)
    WHERE revoked_at IS NULL;

CREATE INDEX assign_rights_anchor_space_idx
    ON assign_rights(anchor_space_id)
    WHERE anchor_space_id IS NOT NULL AND revoked_at IS NULL;

CREATE INDEX assign_rights_anchor_group_idx
    ON assign_rights(anchor_group_id)
    WHERE anchor_group_id IS NOT NULL AND revoked_at IS NULL;


ALTER TABLE users
    ADD COLUMN IF NOT EXISTS password_reset_required_at timestamptz;


CREATE TABLE invitation_tokens (
    id text PRIMARY KEY CHECK (id LIKE 'ivt_%'),
    space_id text NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    email_normalized text NOT NULL,
    member_id text REFERENCES members(id) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX invitation_tokens_active_idx
    ON invitation_tokens (space_id, email_normalized, expires_at)
    WHERE consumed_at IS NULL;


CREATE TABLE sign_in_attempts (
    id text PRIMARY KEY CHECK (id LIKE 'sia_%'),
    user_id text REFERENCES users(id) ON DELETE SET NULL,
    email_normalized text NOT NULL,
    ip text,
    user_agent text,
    failed_attempts integer NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    locked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX sign_in_attempts_active_idx
    ON sign_in_attempts (expires_at)
    WHERE consumed_at IS NULL AND locked_at IS NULL;


-- The migration URL must use the owner role. Deployment provisioning creates
-- both canonical roles; this migration only grants the application role the
-- least privilege needed by the service.
DO $$
BEGIN
    IF current_user <> 'plystra_auth_owner' THEN
        RAISE EXCEPTION 'database migrations must run as plystra_auth_owner (current role: %)', current_user;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'plystra_auth_app') THEN
        RAISE EXCEPTION 'required role plystra_auth_app does not exist';
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO plystra_auth_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO plystra_auth_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO plystra_auth_app;
GRANT SELECT, INSERT ON TABLE audit_logs TO plystra_auth_app;
REVOKE UPDATE, DELETE ON TABLE audit_logs FROM plystra_auth_app;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO plystra_auth_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO plystra_auth_app;


-- River's PostgreSQL schema is kept in the application's forward-only
-- migration stream so the queue is created by the same migration owner as
-- the rest of the Auth database.
CREATE TYPE river_job_state AS ENUM (
    'available',
    'cancelled',
    'completed',
    'discarded',
    'pending',
    'retryable',
    'running',
    'scheduled'
);

CREATE TABLE river_job (
    id bigserial PRIMARY KEY,
    state river_job_state NOT NULL DEFAULT 'available',
    attempt smallint NOT NULL DEFAULT 0,
    max_attempts smallint NOT NULL DEFAULT 25,
    attempted_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    finalized_at timestamptz,
    scheduled_at timestamptz NOT NULL DEFAULT now(),
    priority smallint NOT NULL DEFAULT 1,
    args jsonb NOT NULL,
    attempted_by text[],
    errors jsonb[],
    kind text NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}',
    queue text NOT NULL DEFAULT 'default',
    tags varchar(255)[] NOT NULL DEFAULT '{}',
    unique_key bytea,
    unique_states bit(8),
    CONSTRAINT river_job_finalized_at_state CHECK (
        (finalized_at IS NULL AND state NOT IN ('cancelled', 'completed', 'discarded')) OR
        (finalized_at IS NOT NULL AND state IN ('cancelled', 'completed', 'discarded'))
    ),
    CONSTRAINT river_job_max_attempts_positive CHECK (max_attempts > 0),
    CONSTRAINT river_job_priority_range CHECK (priority BETWEEN 1 AND 4),
    CONSTRAINT river_job_queue_length CHECK (char_length(queue) > 0 AND char_length(queue) < 128),
    CONSTRAINT river_job_kind_length CHECK (char_length(kind) > 0 AND char_length(kind) < 128)
);

CREATE INDEX river_job_kind ON river_job USING btree(kind);
CREATE INDEX river_job_state_and_finalized_at_index ON river_job USING btree(state, finalized_at) WHERE finalized_at IS NOT NULL;
CREATE INDEX river_job_prioritized_fetching_index ON river_job USING btree(state, queue, priority, scheduled_at, id);
CREATE INDEX river_job_args_index ON river_job USING GIN(args);
CREATE INDEX river_job_metadata_index ON river_job USING GIN(metadata);

-- River uses this immutable helper for unique-job state masks.
CREATE OR REPLACE FUNCTION river_job_state_in_bitmask(bitmask bit(8), state river_job_state)
RETURNS boolean
LANGUAGE SQL
IMMUTABLE
AS $$
    SELECT CASE state
        WHEN 'available' THEN get_bit(bitmask, 7)
        WHEN 'cancelled' THEN get_bit(bitmask, 6)
        WHEN 'completed' THEN get_bit(bitmask, 5)
        WHEN 'discarded' THEN get_bit(bitmask, 4)
        WHEN 'pending' THEN get_bit(bitmask, 3)
        WHEN 'retryable' THEN get_bit(bitmask, 2)
        WHEN 'running' THEN get_bit(bitmask, 1)
        WHEN 'scheduled' THEN get_bit(bitmask, 0)
        ELSE 0
    END = 1;
$$;

CREATE UNIQUE INDEX river_job_unique_idx ON river_job (unique_key)
WHERE unique_key IS NOT NULL
  AND unique_states IS NOT NULL
  AND river_job_state_in_bitmask(unique_states, state);

CREATE TABLE river_queue (
    name text PRIMARY KEY NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    metadata jsonb NOT NULL DEFAULT '{}',
    paused_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNLOGGED TABLE river_leader (
    elected_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    leader_id text NOT NULL,
    name text PRIMARY KEY DEFAULT 'default',
    CONSTRAINT river_leader_name CHECK (name = 'default'),
    CONSTRAINT river_leader_id_length CHECK (char_length(leader_id) > 0 AND char_length(leader_id) < 128)
);


-- Policy versions are bumped in the same transaction as authorization writes.
-- PostgreSQL delivers this notification only after that transaction commits,
-- so other nodes never invalidate from an uncommitted policy change.
CREATE OR REPLACE FUNCTION notify_auth_policy_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.policy_version IS DISTINCT FROM NEW.policy_version THEN
        PERFORM pg_notify('auth_policy', NEW.id);
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER spaces_auth_policy_notify
AFTER UPDATE OF policy_version ON spaces
FOR EACH ROW
EXECUTE FUNCTION notify_auth_policy_change();


-- Permission-directory changes are global policy changes. They use a separate
-- monotonic version because no individual Space version can represent them.
CREATE TABLE IF NOT EXISTS authorization_policy_state (
    id boolean PRIMARY KEY DEFAULT TRUE CHECK (id),
    version bigint NOT NULL DEFAULT 1
);

INSERT INTO authorization_policy_state (id, version)
VALUES (TRUE, 1)
ON CONFLICT (id) DO NOTHING;

CREATE OR REPLACE FUNCTION bump_authorization_catalog_version()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    next_version bigint;
BEGIN
    UPDATE authorization_policy_state
    SET version = version + 1
    WHERE id = TRUE
    RETURNING version INTO next_version;
    PERFORM pg_notify('auth_policy', 'catalog:' || next_version::text);
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS permissions_auth_policy_catalog ON permissions;
CREATE TRIGGER permissions_auth_policy_catalog
AFTER INSERT OR UPDATE OR DELETE ON permissions
FOR EACH STATEMENT
EXECUTE FUNCTION bump_authorization_catalog_version();


-- Policy-version changes must also cover direct database writers. The service
-- still performs explicit bumps for multi-step writes that touch role and
-- assignment tables, while these guards cover policy rows that can otherwise
-- leave a cached decision valid after the underlying policy changed.
CREATE OR REPLACE FUNCTION bump_space_policy_for_group_status()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE spaces SET policy_version = policy_version + 1 WHERE id = COALESCE(NEW.space_id, OLD.space_id);
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS groups_auth_policy_status ON groups;
CREATE TRIGGER groups_auth_policy_status
AFTER UPDATE OF status ON groups
FOR EACH ROW
WHEN (OLD.status IS DISTINCT FROM NEW.status)
EXECUTE FUNCTION bump_space_policy_for_group_status();

-- Human member status changes affect every decision in the member's Space.
-- Agent state is intentionally versioned on the member row itself, so it does
-- not invalidate unrelated Space decisions.
CREATE OR REPLACE FUNCTION bump_space_policy_for_human_member_status()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF COALESCE(NEW.type, OLD.type) <> 'agent' THEN
        UPDATE spaces SET policy_version = policy_version + 1 WHERE id = COALESCE(NEW.space_id, OLD.space_id);
    END IF;
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS members_auth_policy_status ON members;
CREATE TRIGGER members_auth_policy_status
AFTER UPDATE OF status ON members
FOR EACH ROW
WHEN (OLD.status IS DISTINCT FROM NEW.status)
EXECUTE FUNCTION bump_space_policy_for_human_member_status();

-- Grants are policy rows. Service grant writes rely on this trigger so that
-- direct writers and other service instances use the same version path.
CREATE OR REPLACE FUNCTION bump_space_policy_for_grant_revocation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE spaces SET policy_version = policy_version + 1 WHERE id = COALESCE(NEW.space_id, OLD.space_id);
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS grants_auth_policy_revocation ON authorization_grants;
DROP TRIGGER IF EXISTS grants_auth_policy_mutation ON authorization_grants;
CREATE TRIGGER grants_auth_policy_mutation
AFTER INSERT OR UPDATE OR DELETE ON authorization_grants
FOR EACH ROW
EXECUTE FUNCTION bump_space_policy_for_grant_revocation();

-- Group membership changes alter the resource facts used by scoped grants.
CREATE OR REPLACE FUNCTION bump_space_policy_for_group_membership()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    affected_group text := COALESCE(NEW.group_id, OLD.group_id);
BEGIN
    UPDATE spaces
    SET policy_version = policy_version + 1
    WHERE id = (SELECT space_id FROM groups WHERE id = affected_group);
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS group_members_auth_policy_mutation ON group_members;
CREATE TRIGGER group_members_auth_policy_mutation
AFTER INSERT OR UPDATE OR DELETE ON group_members
FOR EACH ROW
EXECUTE FUNCTION bump_space_policy_for_group_membership();

-- Envelope rows are policy facts and must invalidate the owning Space.
CREATE OR REPLACE FUNCTION bump_space_policy_for_envelope()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    new_row jsonb := to_jsonb(NEW);
    old_row jsonb := to_jsonb(OLD);
    affected_space text := COALESCE(new_row ->> 'space_id', old_row ->> 'space_id');
    affected_group text := COALESCE(new_row ->> 'group_id', old_row ->> 'group_id');
BEGIN
    IF affected_space IS NULL AND affected_group IS NOT NULL THEN
        SELECT space_id INTO affected_space FROM groups WHERE id = affected_group;
    END IF;
    UPDATE spaces SET policy_version = policy_version + 1 WHERE id = affected_space;
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS space_envelopes_auth_policy_mutation ON space_envelopes;
CREATE TRIGGER space_envelopes_auth_policy_mutation
AFTER INSERT OR UPDATE OR DELETE ON space_envelopes
FOR EACH ROW
EXECUTE FUNCTION bump_space_policy_for_envelope();

DROP TRIGGER IF EXISTS space_envelope_entries_auth_policy_mutation ON space_envelope_entries;
CREATE TRIGGER space_envelope_entries_auth_policy_mutation
AFTER INSERT OR UPDATE OR DELETE ON space_envelope_entries
FOR EACH ROW
EXECUTE FUNCTION bump_space_policy_for_envelope();

DROP TRIGGER IF EXISTS group_envelopes_auth_policy_mutation ON group_envelopes;
CREATE TRIGGER group_envelopes_auth_policy_mutation
AFTER INSERT OR UPDATE OR DELETE ON group_envelopes
FOR EACH ROW
EXECUTE FUNCTION bump_space_policy_for_envelope();

DROP TRIGGER IF EXISTS group_envelope_entries_auth_policy_mutation ON group_envelope_entries;
CREATE TRIGGER group_envelope_entries_auth_policy_mutation
AFTER INSERT OR UPDATE OR DELETE ON group_envelope_entries
FOR EACH ROW
EXECUTE FUNCTION bump_space_policy_for_envelope();


-- Existing administrator roles must retain the built-in permission required by
-- the standard-group management endpoint introduced after the initial seed.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'administrator' AND p.key = 'auth.groups:manage'
ON CONFLICT DO NOTHING;


ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name text NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url text NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS public_metadata jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE users ADD COLUMN IF NOT EXISTS private_metadata jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE users ADD CONSTRAINT users_public_metadata_object_check
    CHECK (jsonb_typeof(public_metadata) = 'object');
ALTER TABLE users ADD CONSTRAINT users_private_metadata_object_check
    CHECK (jsonb_typeof(private_metadata) = 'object');


-- Operators and member bindings are mutually exclusive identities. Check the
-- existing data before installing the guards so a partially migrated database
-- fails closed with an actionable error.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM operators o
        JOIN user_members um ON um.user_id = o.user_id
        WHERE um.status = 'active'
          AND um.revoked_at IS NULL
          AND (um.expires_at IS NULL OR um.expires_at > now())
    ) THEN
        RAISE EXCEPTION 'operators and active member bindings are mutually exclusive';
    END IF;
END
$$;

-- A member binding cannot be created or reactivated for an operator identity.
-- The check remains in the database so direct writers cannot bypass the
-- service-level validation.
CREATE OR REPLACE FUNCTION reject_operator_member_binding() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status = 'active'
       AND NEW.revoked_at IS NULL
       AND (NEW.expires_at IS NULL OR NEW.expires_at > now())
       AND EXISTS (SELECT 1 FROM operators WHERE user_id = NEW.user_id)
    THEN
        RAISE EXCEPTION 'operator identities cannot have active member bindings' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS user_members_operator_exclusion ON user_members;
CREATE TRIGGER user_members_operator_exclusion
BEFORE INSERT OR UPDATE OF user_id, status, expires_at, revoked_at ON user_members
FOR EACH ROW EXECUTE FUNCTION reject_operator_member_binding();

-- An operator cannot be created for a user who already has an active member
-- binding. This protects direct SQL writers as well as the operations plane.
CREATE OR REPLACE FUNCTION reject_member_operator_identity() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM user_members
        WHERE user_id = NEW.user_id
          AND status = 'active'
          AND revoked_at IS NULL
          AND (expires_at IS NULL OR expires_at > now())
    ) THEN
        RAISE EXCEPTION 'active member identities cannot become operators' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS operators_member_exclusion ON operators;
CREATE TRIGGER operators_member_exclusion
BEFORE INSERT OR UPDATE OF user_id ON operators
FOR EACH ROW EXECUTE FUNCTION reject_member_operator_identity();


-- Agent groups are part of the delegation tree and are not ordinary groups.
-- Keep the invariant in PostgreSQL as well as in the service so direct writers
-- cannot create a group layout the authorization evaluator does not understand.
-- Human and application owners get a top-level Agent group; an Agent owner
-- gets a child group directly below its own home group. Standard groups may
-- never be created below an Agent group.
CREATE OR REPLACE FUNCTION enforce_agent_group_structure() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    owner_type text;
    owner_home_group text;
    parent_kind text;
    parent_space text;
BEGIN
    IF TG_OP = 'UPDATE' AND OLD.kind = 'agents' AND (
        NEW.kind IS DISTINCT FROM OLD.kind
        OR NEW.owner_member_id IS DISTINCT FROM OLD.owner_member_id
        OR NEW.parent_id IS DISTINCT FROM OLD.parent_id
    ) THEN
        RAISE EXCEPTION 'Agent groups cannot be moved or transferred' USING ERRCODE = '42501';
    END IF;

    IF NEW.kind = 'agents' THEN
        IF NEW.owner_member_id IS NULL THEN
            RAISE EXCEPTION 'Agent groups require an owner member' USING ERRCODE = '23514';
        END IF;

        SELECT m.type, m.home_group_id
        INTO owner_type, owner_home_group
        FROM members m
        WHERE m.id = NEW.owner_member_id;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'Agent group owner does not exist' USING ERRCODE = '23503';
        END IF;

        IF owner_type IN ('human', 'application') THEN
            IF NEW.parent_id IS NOT NULL THEN
                RAISE EXCEPTION 'Human and application Agent groups must be top-level' USING ERRCODE = '23514';
            END IF;
        ELSIF owner_type = 'agent' THEN
            IF owner_home_group IS NULL OR NEW.parent_id IS DISTINCT FROM owner_home_group THEN
                RAISE EXCEPTION 'An Agent group must be directly below its owner home group' USING ERRCODE = '23514';
            END IF;
            SELECT g.kind, g.space_id
            INTO parent_kind, parent_space
            FROM groups g
            WHERE g.id = NEW.parent_id;
            IF NOT FOUND OR parent_kind <> 'agents' OR parent_space <> NEW.space_id THEN
                RAISE EXCEPTION 'An Agent group parent must be an Agent group in the same Space' USING ERRCODE = '23514';
            END IF;
        ELSE
            RAISE EXCEPTION 'Agent group owner has an invalid member type' USING ERRCODE = '23514';
        END IF;
    ELSE
        IF NEW.owner_member_id IS NOT NULL THEN
            RAISE EXCEPTION 'Standard groups cannot have an Agent owner' USING ERRCODE = '23514';
        END IF;
        IF NEW.parent_id IS NOT NULL THEN
            SELECT g.kind INTO parent_kind FROM groups g WHERE g.id = NEW.parent_id;
            IF parent_kind = 'agents' THEN
                RAISE EXCEPTION 'Standard groups cannot be children of Agent groups' USING ERRCODE = '42501';
            END IF;
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS groups_agent_structure_guard ON groups;
CREATE TRIGGER groups_agent_structure_guard
    BEFORE INSERT OR UPDATE OF kind, owner_member_id, parent_id ON groups
    FOR EACH ROW EXECUTE FUNCTION enforce_agent_group_structure();


ALTER TABLE factors ADD COLUMN IF NOT EXISTS secret_hash bytea;

ALTER TABLE factors DROP CONSTRAINT IF EXISTS factors_backup_code_storage_check;
ALTER TABLE factors ADD CONSTRAINT factors_backup_code_storage_check CHECK (
    (kind = 'backup_code' AND secret_hash IS NOT NULL AND secret_ciphertext IS NULL)
    OR kind <> 'backup_code'
);


-- Tombstoned members and Agent groups retain identity references for audit and
-- self scope resolution, but they must never retain live authority. Keep this
-- invariant in PostgreSQL so direct writers and concurrent service instances
-- cannot re-grant a removed principal.
CREATE OR REPLACE FUNCTION reject_tombstone_authorization_grant()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.revoked_at IS NULL
       AND NEW.grantee_member_id IS NOT NULL
       AND EXISTS (
           SELECT 1 FROM members
           WHERE id = NEW.grantee_member_id AND status = 'removed'
       ) THEN
        RAISE EXCEPTION 'removed members cannot hold authorization grants' USING ERRCODE = '42501';
    END IF;
    IF NEW.revoked_at IS NULL
       AND NEW.grantee_group_id IS NOT NULL
       AND EXISTS (
           SELECT 1 FROM groups
           WHERE id = NEW.grantee_group_id AND status = 'removed'
       ) THEN
        RAISE EXCEPTION 'removed groups cannot hold authorization grants' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS authorization_grants_tombstone_guard ON authorization_grants;
CREATE TRIGGER authorization_grants_tombstone_guard
    BEFORE INSERT OR UPDATE ON authorization_grants
    FOR EACH ROW EXECUTE FUNCTION reject_tombstone_authorization_grant();

-- Revocation must also happen for direct database status changes. The row is
-- retained for audit, but no active grant may survive the tombstone transition.
CREATE OR REPLACE FUNCTION revoke_tombstone_member_grants()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE authorization_grants
    SET revoked_at = now()
    WHERE grantee_member_id = NEW.id
      AND revoked_at IS NULL;
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS members_tombstone_grants ON members;
CREATE TRIGGER members_tombstone_grants
    AFTER UPDATE OF status ON members
    FOR EACH ROW
    WHEN (OLD.status IS DISTINCT FROM NEW.status AND NEW.status = 'removed')
    EXECUTE FUNCTION revoke_tombstone_member_grants();

CREATE OR REPLACE FUNCTION revoke_tombstone_group_grants()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE authorization_grants
    SET revoked_at = now()
    WHERE grantee_group_id = NEW.id
      AND revoked_at IS NULL;
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS groups_tombstone_grants ON groups;
CREATE TRIGGER groups_tombstone_grants
    AFTER UPDATE OF status ON groups
    FOR EACH ROW
    WHEN (OLD.status IS DISTINCT FROM NEW.status AND NEW.status = 'removed')
    EXECUTE FUNCTION revoke_tombstone_group_grants();

UPDATE authorization_grants ag
SET revoked_at = now()
FROM members m
WHERE ag.grantee_member_id = m.id
  AND m.status = 'removed'
  AND ag.revoked_at IS NULL;

UPDATE authorization_grants ag
SET revoked_at = now()
FROM groups g
WHERE ag.grantee_group_id = g.id
  AND g.status = 'removed'
  AND ag.revoked_at IS NULL;


-- OAuth authorization codes are opaque, short-lived credentials. Keep only a
-- digest in the database and bind the code to the consented Agent member,
-- client nonce, and resource indicator.
ALTER TABLE authorization_codes
    ADD COLUMN IF NOT EXISTS code_hash bytea,
    ADD COLUMN IF NOT EXISTS member_id text REFERENCES members(id),
    ADD COLUMN IF NOT EXISTS nonce text,
    ADD COLUMN IF NOT EXISTS resource text;

CREATE UNIQUE INDEX IF NOT EXISTS authorization_codes_hash_idx
    ON authorization_codes(code_hash)
    WHERE code_hash IS NOT NULL;


ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS step_up_operation text,
    ADD COLUMN IF NOT EXISTS step_up_digest bytea,
    ADD COLUMN IF NOT EXISTS step_up_expires_at timestamptz;

CREATE INDEX IF NOT EXISTS sessions_step_up_idx
    ON sessions(id, step_up_expires_at)
    WHERE step_up_operation IS NOT NULL;


ALTER TABLE sign_in_attempts ADD COLUMN password_verified_at timestamptz;

ALTER TABLE sessions
    ADD COLUMN auth_methods text[] NOT NULL DEFAULT ARRAY['pwd']::text[],
    ADD CONSTRAINT sessions_auth_methods_nonempty CHECK (cardinality(auth_methods) > 0);


ALTER TABLE sessions
    ADD COLUMN step_up_method text
    CONSTRAINT sessions_step_up_method_check CHECK (step_up_method IN ('totp', 'password'));


CREATE TABLE pending_invitation_registrations (
    user_id text PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    invitation_id text NOT NULL UNIQUE REFERENCES invitation_tokens(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now()
);


CREATE TABLE passkey_challenges (
    id text PRIMARY KEY CHECK (id LIKE 'pch_%'),
    user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id text NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    name text NOT NULL,
    session_data jsonb NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX passkey_challenges_active_idx ON passkey_challenges (user_id, expires_at)
    WHERE consumed_at IS NULL;

CREATE UNIQUE INDEX factors_webauthn_credential_id_idx ON factors (credential_id)
    WHERE kind = 'webauthn';


ALTER TABLE sign_in_attempts
    ADD COLUMN method text NOT NULL DEFAULT 'password' CHECK (method IN ('password', 'passkey')),
    ADD COLUMN passkey_session jsonb;

ALTER TABLE sign_in_attempts
    ADD CONSTRAINT sign_in_attempts_passkey_session_check
    CHECK ((method = 'passkey') = (passkey_session IS NOT NULL));


ALTER TABLE invitation_tokens
    ADD COLUMN inviter_member_id text REFERENCES members(id) ON DELETE SET NULL,
    ADD COLUMN inviter_user_id text REFERENCES users(id) ON DELETE SET NULL;


CREATE TABLE approval_requests (
    id text PRIMARY KEY CHECK (left(id, 4) = 'apr_'),
    agent_member_id text NOT NULL REFERENCES members(id),
    approver_member_id text NOT NULL REFERENCES members(id),
    permission_key text NOT NULL,
    resource_type text NOT NULL CHECK (resource_type <> ''),
    resource_id text NOT NULL CHECK (resource_id <> ''),
    resource_space_id text NOT NULL REFERENCES spaces(id),
    resource_group_id text,
    resource_owner_member_id text,
    request_digest bytea NOT NULL CHECK (length(request_digest) = 32),
    reason text NOT NULL DEFAULT '',
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'rejected', 'consumed')),
    expires_at timestamptz NOT NULL,
    decided_by_user_id text REFERENCES users(id),
    decided_at timestamptz,
    approved_expires_at timestamptz,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((status = 'pending' AND decided_by_user_id IS NULL AND decided_at IS NULL)
        OR (status <> 'pending' AND decided_by_user_id IS NOT NULL AND decided_at IS NOT NULL))
);

CREATE INDEX approval_requests_inbox_idx
    ON approval_requests (approver_member_id, created_at DESC)
    WHERE status = 'pending';

CREATE INDEX approval_requests_approved_idx
    ON approval_requests (agent_member_id, permission_key, resource_space_id, created_at DESC)
    WHERE status = 'approved';


ALTER TABLE approval_requests
    ADD COLUMN kind text NOT NULL DEFAULT 'business'
        CHECK (kind IN ('business', 'governance')),
    ADD COLUMN operation text,
    ADD COLUMN request_details jsonb;

ALTER TABLE approval_requests
    ADD CONSTRAINT approval_requests_governance_details_check
    CHECK ((kind = 'business' AND operation IS NULL AND request_details IS NULL)
        OR (kind = 'governance' AND operation IS NOT NULL AND operation <> '' AND request_details IS NOT NULL));


ALTER TABLE applications
    ADD COLUMN manifest_permissions jsonb NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(manifest_permissions) = 'array'),
    ADD COLUMN visibility text NOT NULL DEFAULT 'private'
        CHECK (visibility IN ('private', 'public')),
    ADD COLUMN status text NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended'));


CREATE TABLE application_installations (
    id text PRIMARY KEY CHECK (id LIKE 'ins_%'),
    application_id text NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    space_id text NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    member_id text NOT NULL UNIQUE REFERENCES members(id) ON DELETE CASCADE,
    role_id text NOT NULL UNIQUE REFERENCES roles(id) ON DELETE CASCADE,
    scope text NOT NULL CHECK (scope IN ('space', 'space_tree', 'group', 'group_tree')),
    anchor_group_id text REFERENCES groups(id),
    approved_permissions jsonb NOT NULL CHECK (jsonb_typeof(approved_permissions) = 'array'),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'uninstalled')),
    installed_by text NOT NULL REFERENCES members(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((scope IN ('group', 'group_tree')) = (anchor_group_id IS NOT NULL))
);

CREATE UNIQUE INDEX application_installations_current_unique
    ON application_installations (application_id, space_id)
    WHERE status <> 'uninstalled';

CREATE INDEX application_installations_application_idx
    ON application_installations (application_id, status);


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


-- Existing SHA-256 digests are wrapped with the deployment HMAC key by the
-- service before it accepts requests. New keys are HMAC-protected at creation.
-- Stop the old binary before applying this migration: it cannot authenticate
-- converted keys and would label newly inserted SHA-256 hashes as HMAC hashes.
ALTER TABLE api_keys
    ADD COLUMN hash_scheme text NOT NULL DEFAULT 'sha256_legacy'
        CHECK (hash_scheme IN ('sha256_legacy', 'hmac_sha256'));

ALTER TABLE api_keys ALTER COLUMN hash_scheme SET DEFAULT 'hmac_sha256';


-- A rotated secret remains usable for 24 hours unless the parent key expires
-- or is revoked sooner. Multiple rotations retain independent grace windows.
CREATE TABLE api_key_grace_secrets (
    key_id text NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    secret_hash bytea NOT NULL CHECK (length(secret_hash) = 32),
    valid_until timestamptz NOT NULL,
    PRIMARY KEY (key_id, secret_hash)
);
CREATE INDEX api_key_grace_secrets_expiry_idx ON api_key_grace_secrets(valid_until);

-- An empty allowlist accepts any direct client IP. Existing keys keep that
-- behavior until their owner explicitly restricts them.
ALTER TABLE api_keys
    ADD COLUMN allowed_ip_cidrs jsonb NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(allowed_ip_cidrs) = 'array');


-- Reject new keys without an expiry while allowing old rows with no expiry to
-- be revoked. NOT VALID avoids rewriting historical rows during deployment;
-- authentication rejects any remaining row whose expiry is NULL.
ALTER TABLE api_keys ADD CONSTRAINT api_keys_expiry_required
    CHECK (expires_at IS NOT NULL OR revoked_at IS NOT NULL) NOT VALID;


-- The published manifest is the effective maximum. A public application starts
-- with no effective permissions until an operator approves its pending request.
ALTER TABLE applications
    ADD COLUMN review_status text NOT NULL DEFAULT 'not_required'
        CHECK (review_status IN ('not_required', 'pending', 'approved', 'rejected')),
    ADD COLUMN pending_manifest_permissions jsonb
        CHECK (pending_manifest_permissions IS NULL OR jsonb_typeof(pending_manifest_permissions) = 'array'),
    ADD CONSTRAINT applications_review_visibility_check CHECK (
        (visibility = 'private' AND review_status = 'not_required' AND pending_manifest_permissions IS NULL)
        OR
        (visibility = 'public' AND review_status <> 'not_required')
    );


-- Keep the pre-consent request separate from authorization codes. The public
-- request handle is never stored; only its SHA-256 digest can locate the row.
CREATE TABLE oauth_authorization_requests (
    id text PRIMARY KEY CHECK (left(id, 4) = 'arq_'),
    request_hash bytea NOT NULL UNIQUE CHECK (length(request_hash) = 32),
    application_id text NOT NULL REFERENCES applications(id),
    redirect_uri text NOT NULL CHECK (redirect_uri <> ''),
    code_challenge text NOT NULL CHECK (code_challenge <> ''),
    scope text NOT NULL CHECK (scope <> ''),
    state text NOT NULL CHECK (state <> ''),
    nonce text NOT NULL CHECK (nonce <> ''),
    resource text NOT NULL CHECK (resource <> ''),
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'denied')),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((status = 'pending' AND consumed_at IS NULL)
        OR (status <> 'pending' AND consumed_at IS NOT NULL))
);

CREATE INDEX oauth_authorization_requests_pending_expiry_idx
    ON oauth_authorization_requests (expires_at)
    WHERE status = 'pending';


-- A live OAuth authorization has exactly one Agent for each owner and client.
-- If an older deployment contains duplicates, migration must stop for an
-- explicit reconciliation rather than silently discard grants or credentials.
CREATE UNIQUE INDEX members_oauth_owner_client_unique
    ON members (created_by_member_id, oauth_client_id)
    WHERE type = 'agent' AND source = 'oauth' AND status <> 'removed';


-- Authorization identities are immutable event snapshots, not foreign keys:
-- deleting credentials or tombstoning members must not erase audit evidence.
-- Historical rows keep empty context; do not infer past identities from today.
-- Resource locations are request facts and can be malformed in denied requests;
-- only verified identity columns enforce typed ID prefixes.
ALTER TABLE audit_logs
    ADD COLUMN plane text NOT NULL DEFAULT '',
    ADD COLUMN credential_type text NOT NULL DEFAULT '',
    ADD COLUMN space_id text,
    ADD COLUMN resource_group_id text,
    ADD COLUMN member_id text CHECK (member_id IS NULL OR left(member_id, 4) = 'mem_'),
    ADD COLUMN member_type text CHECK (member_type IN ('human', 'agent', 'application')),
    ADD COLUMN user_id text CHECK (user_id IS NULL OR left(user_id, 4) = 'usr_'),
    ADD COLUMN application_id text CHECK (application_id IS NULL OR left(application_id, 4) = 'app_'),
    ADD COLUMN owner_chain jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(owner_chain) = 'array'),
    ADD COLUMN decision_id text CHECK (decision_id IS NULL OR left(decision_id, 4) = 'dec_'),
    ADD COLUMN deny_code text,
    ADD COLUMN permission_key text,
    ADD COLUMN policy_version bigint,
    ADD CONSTRAINT audit_member_identity_check CHECK ((member_id IS NULL) = (member_type IS NULL));

CREATE INDEX audit_logs_space_cursor_idx ON audit_logs(space_id, occurred_at DESC, id DESC);
CREATE INDEX audit_logs_member_cursor_idx ON audit_logs(member_id, occurred_at DESC, id DESC);
CREATE INDEX audit_logs_decision_idx ON audit_logs(decision_id) WHERE decision_id IS NOT NULL;


-- Audit queries correlate a member with events from its delegated descendants.
-- Snapshots remain immutable; this index does not reconstruct historical chains.
CREATE INDEX audit_logs_owner_chain_idx ON audit_logs USING gin(owner_chain jsonb_path_ops);


-- Agent-local changes invalidate the Agent and delegated descendants through
-- member versions. They must not invalidate unrelated Space authority. Keep
-- the same rules for direct database writers and application transactions.
CREATE OR REPLACE FUNCTION bump_space_policy_for_group_status()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.kind = 'agents' THEN
        UPDATE members SET version = version + 1
        WHERE home_group_id = NEW.id AND type = 'agent';
    ELSE
        UPDATE spaces SET policy_version = policy_version + 1 WHERE id = NEW.space_id;
    END IF;
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION bump_space_policy_for_grant_revocation()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    affected record;
BEGIN
    FOR affected IN
        SELECT DISTINCT v.space_id, v.member_id, v.group_id
        FROM (VALUES (OLD.space_id, OLD.grantee_member_id, OLD.grantee_group_id),
                     (NEW.space_id, NEW.grantee_member_id, NEW.grantee_group_id))
             AS v(space_id, member_id, group_id)
        WHERE v.space_id IS NOT NULL
    LOOP
        IF EXISTS (SELECT 1 FROM members WHERE id = affected.member_id AND type = 'agent') THEN
            UPDATE members SET version = version + 1 WHERE id = affected.member_id;
        ELSIF EXISTS (SELECT 1 FROM groups WHERE id = affected.group_id AND kind = 'agents') THEN
            UPDATE members SET version = version + 1
            WHERE home_group_id = affected.group_id AND type = 'agent';
        ELSE
            UPDATE spaces SET policy_version = policy_version + 1 WHERE id = affected.space_id;
        END IF;
    END LOOP;
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION bump_space_policy_for_group_membership()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    affected record;
BEGIN
    FOR affected IN
        SELECT DISTINCT v.group_id, v.member_id
        FROM (VALUES (OLD.group_id, OLD.member_id), (NEW.group_id, NEW.member_id))
             AS v(group_id, member_id)
        WHERE v.group_id IS NOT NULL
    LOOP
        IF EXISTS (SELECT 1 FROM members WHERE id = affected.member_id AND type = 'agent') THEN
            UPDATE members SET version = version + 1 WHERE id = affected.member_id;
        ELSE
            UPDATE spaces SET policy_version = policy_version + 1
            WHERE id = (SELECT space_id FROM groups WHERE id = affected.group_id);
        END IF;
    END LOOP;
    RETURN NULL;
END;
$$;

-- Credential security state participates in Agent cache versions; updating a
-- key's usage timestamp alone does not change its authority or validity.
CREATE FUNCTION bump_agent_policy_for_credential()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND ROW(OLD.member_id, OLD.kind, OLD.prefix, OLD.secret_hash, OLD.family_id, OLD.expires_at, OLD.revoked_at)
           IS NOT DISTINCT FROM
           ROW(NEW.member_id, NEW.kind, NEW.prefix, NEW.secret_hash, NEW.family_id, NEW.expires_at, NEW.revoked_at)
       AND (NEW.kind <> 'oauth_refresh' OR OLD.last_used_at IS NOT DISTINCT FROM NEW.last_used_at) THEN
        RETURN NULL;
    END IF;
    UPDATE members SET version = version + 1
    WHERE type = 'agent' AND id IN (OLD.member_id, NEW.member_id);
    RETURN NULL;
END;
$$;

CREATE TRIGGER agent_credentials_auth_policy_mutation
AFTER INSERT OR UPDATE OR DELETE ON agent_credentials
FOR EACH ROW EXECUTE FUNCTION bump_agent_policy_for_credential();


-- Grant configuration is filtered by Space and traversed in creation order.
-- Keep revoked tombstones out of the listing index without deleting history.
CREATE INDEX authorization_grants_space_listing_idx
    ON authorization_grants(space_id, created_at DESC, id DESC)
    WHERE revoked_at IS NULL;


-- A resumed Agent must not revalidate access tokens issued before suspension.
-- Keep this separate from authority versions: grant changes must still be
-- evaluated using the token's scope and the current authorization facts.
ALTER TABLE members ADD COLUMN token_epoch bigint NOT NULL DEFAULT 1 CHECK (token_epoch > 0);

CREATE FUNCTION invalidate_agent_tokens_on_deactivation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.type = 'agent' AND OLD.status = 'active' AND NEW.status <> 'active' THEN
        NEW.token_epoch := OLD.token_epoch + 1;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER members_agent_token_deactivation
BEFORE UPDATE OF status ON members
FOR EACH ROW EXECUTE FUNCTION invalidate_agent_tokens_on_deactivation();


-- Authorization codes cannot restore credentials revoked by Agent suspension.
-- Bind new codes to the existing Agent token epoch. Legacy codes deliberately
-- remain unbound and fail closed: their issue-time epoch cannot be recovered.
ALTER TABLE authorization_codes
    ADD COLUMN member_token_epoch bigint CHECK (member_token_epoch > 0);


-- A suspended standard root still owns its place in the Space tree. Removed
-- roots are tombstones; Agent-owned trees have their own ownership constraints.
-- Existing duplicate live roots make this migration fail without changing
-- their identities, grants, memberships, or parent relationships.
CREATE UNIQUE INDEX groups_standard_root_unique ON groups (space_id)
    WHERE kind = 'standard' AND parent_id IS NULL AND status <> 'removed';


CREATE TABLE IF NOT EXISTS sso_connections (
    id text PRIMARY KEY CHECK (id LIKE 'con_%'),
    space_id text NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
    provider text NOT NULL CHECK (provider IN ('oidc')),
    issuer text NOT NULL,
    client_id text NOT NULL CHECK (length(client_id) BETWEEN 1 AND 512),
    client_secret_ciphertext bytea NOT NULL,
    redirect_uri text NOT NULL,
    groups_claim text NOT NULL DEFAULT 'groups' CHECK (length(groups_claim) BETWEEN 1 AND 128),
    role_mappings jsonb NOT NULL DEFAULT '{}'::jsonb,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (space_id, name),
    CHECK (jsonb_typeof(role_mappings) = 'object')
);
CREATE INDEX IF NOT EXISTS sso_connections_space_idx ON sso_connections(space_id, status, created_at);

CREATE TABLE IF NOT EXISTS sso_states (
    id text PRIMARY KEY CHECK (id LIKE 'sos_%'),
    connection_id text NOT NULL REFERENCES sso_connections(id) ON DELETE CASCADE,
    state_hash bytea NOT NULL UNIQUE,
    nonce_hash bytea NOT NULL,
    pkce_verifier_ciphertext bytea NOT NULL,
    redirect_uri text NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sso_states_expiry_idx ON sso_states(expires_at) WHERE consumed_at IS NULL;

CREATE TABLE IF NOT EXISTS external_identities (
    id text PRIMARY KEY CHECK (id LIKE 'ext_%'),
    user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    issuer text NOT NULL,
    subject text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (issuer, subject),
    UNIQUE (user_id, issuer, subject)
);
CREATE INDEX IF NOT EXISTS external_identities_user_idx ON external_identities(user_id);


-- Every Space administrator must be able to configure enterprise login. The
-- operation still requires human step-up and the authorization engine, while
-- Agent use remains subject to the catalog's approval rule.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON p.key = 'auth.connections:manage'
WHERE r.name = 'administrator' AND r.managed = true
ON CONFLICT DO NOTHING;


CREATE TABLE IF NOT EXISTS sso_domains (
    id text PRIMARY KEY CHECK (id LIKE 'dom_%'),
    space_id text NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    domain text NOT NULL,
    verification_token_hash bytea NOT NULL,
    connection_id text REFERENCES sso_connections(id) ON DELETE SET NULL,
    force_sso boolean NOT NULL DEFAULT false,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'verified', 'disabled')),
    verified_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (domain),
    UNIQUE (space_id, domain),
    CHECK (domain = lower(domain)),
    CHECK (force_sso = false OR connection_id IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS sso_domains_space_idx ON sso_domains(space_id, status, created_at);


ALTER TABLE sso_connections
    DROP CONSTRAINT IF EXISTS sso_connections_provider_check;
ALTER TABLE sso_connections
    ADD CONSTRAINT sso_connections_provider_check CHECK (provider IN ('oidc', 'saml'));
ALTER TABLE sso_connections
    ALTER COLUMN client_secret_ciphertext DROP NOT NULL;
ALTER TABLE sso_connections
    ADD COLUMN IF NOT EXISTS saml_entity_id text,
    ADD COLUMN IF NOT EXISTS saml_sso_url text,
    ADD COLUMN IF NOT EXISTS saml_sso_binding text,
    ADD COLUMN IF NOT EXISTS saml_idp_certificate text;
ALTER TABLE sso_states
    ADD COLUMN IF NOT EXISTS request_id text;


ALTER TABLE sso_connections
    ADD COLUMN IF NOT EXISTS covers_subtree boolean NOT NULL DEFAULT false;

ALTER TABLE sso_domains
    ADD COLUMN IF NOT EXISTS covers_subtree boolean NOT NULL DEFAULT false;


CREATE TABLE IF NOT EXISTS directories (
    id text PRIMARY KEY CHECK (id LIKE 'dir_%'),
    space_id text NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
    token_prefix text NOT NULL UNIQUE,
    token_hash bytea NOT NULL UNIQUE,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (space_id, name)
);
CREATE INDEX IF NOT EXISTS directories_space_idx ON directories(space_id, status, created_at);

CREATE TABLE IF NOT EXISTS directory_users (
    id text PRIMARY KEY CHECK (id LIKE 'dusr_%'),
    directory_id text NOT NULL REFERENCES directories(id) ON DELETE CASCADE,
    external_id text NOT NULL CHECK (length(external_id) BETWEEN 1 AND 512),
    user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    member_id text NOT NULL REFERENCES members(id) ON DELETE CASCADE,
    user_name text NOT NULL,
    display_name text NOT NULL DEFAULT '',
    active boolean NOT NULL DEFAULT true,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (directory_id, external_id),
    UNIQUE (directory_id, user_id),
    UNIQUE (directory_id, member_id)
);
CREATE INDEX IF NOT EXISTS directory_users_directory_idx ON directory_users(directory_id, active, created_at);

CREATE TABLE IF NOT EXISTS directory_groups (
    id text PRIMARY KEY CHECK (id LIKE 'dgrp_%'),
    directory_id text NOT NULL REFERENCES directories(id) ON DELETE CASCADE,
    external_id text NOT NULL CHECK (length(external_id) BETWEEN 1 AND 512),
    group_id text NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    display_name text NOT NULL,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (directory_id, external_id),
    UNIQUE (directory_id, group_id)
);
CREATE INDEX IF NOT EXISTS directory_groups_directory_idx ON directory_groups(directory_id, created_at);

CREATE TABLE IF NOT EXISTS directory_group_members (
    directory_group_id text NOT NULL REFERENCES directory_groups(id) ON DELETE CASCADE,
    member_id text NOT NULL REFERENCES members(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (directory_group_id, member_id)
);


-- Preserve deleted external identities permanently; deactivation is reversible,
-- deletion is not. Existing inactive resources remain deactivated, not deleted.
ALTER TABLE directory_users ADD COLUMN deleted_at timestamptz;
ALTER TABLE directory_users ADD CONSTRAINT directory_users_deleted_inactive
    CHECK (deleted_at IS NULL OR NOT active);
ALTER TABLE directory_groups ADD COLUMN deleted_at timestamptz;

-- Legacy directories have no trustworthy configurator. Positive authority
-- changes fail closed until an authenticated administrator rotates the token.
ALTER TABLE directories ADD COLUMN configured_by_member_id text REFERENCES members(id);
ALTER TABLE directories ADD COLUMN configured_by_user_id text REFERENCES users(id);


-- A directory trusts an explicitly selected connection and stable claim,
-- never an email coincidence. Enforce tenant ownership in the database too.
ALTER TABLE sso_connections ADD CONSTRAINT sso_connections_id_space_unique UNIQUE (id, space_id);
ALTER TABLE directories ADD COLUMN sso_connection_id text;
ALTER TABLE directories ADD COLUMN sso_identity_claim text;
ALTER TABLE directories ADD CONSTRAINT directories_sso_connection_space_fk
    FOREIGN KEY (sso_connection_id, space_id) REFERENCES sso_connections(id, space_id);
ALTER TABLE directories ADD CONSTRAINT directories_sso_identity_pair CHECK (
    (sso_connection_id IS NULL AND sso_identity_claim IS NULL)
    OR (sso_connection_id IS NOT NULL AND sso_identity_claim IS NOT NULL
        AND length(sso_identity_claim) BETWEEN 1 AND 512)
);
CREATE UNIQUE INDEX directories_active_sso_connection_unique
    ON directories(sso_connection_id) WHERE status = 'active' AND sso_connection_id IS NOT NULL;

-- Keep directory provenance after unlinking or offboarding so a later SSO
-- callback cannot silently recreate a revoked binding through the JIT path.
ALTER TABLE external_identities ADD COLUMN directory_user_id text REFERENCES directory_users(id);
CREATE INDEX external_identities_directory_user_idx ON external_identities(directory_user_id)
    WHERE directory_user_id IS NOT NULL;


-- Publishers opt their clients into human OIDC sign-in independently of
-- business permissions. Existing clients retain their original behavior.
ALTER TABLE applications ADD COLUMN human_oidc_enabled boolean NOT NULL DEFAULT false;

-- JIT role mappings use the configuring identity's current assignment rights.
-- Older connections keep their data and have no inferred configurator.
ALTER TABLE sso_connections
    ADD COLUMN configured_by_member_id text REFERENCES members(id),
    ADD COLUMN configured_by_user_id text REFERENCES users(id),
    ADD CONSTRAINT sso_configurator_user_requires_member
        CHECK (configured_by_user_id IS NULL OR configured_by_member_id IS NOT NULL);


ALTER TABLE sessions ADD COLUMN sso_member_id text REFERENCES members(id);

-- Old enterprise sessions can already have switched away from their login member.
UPDATE sessions SET revoked_at = now()
WHERE revoked_at IS NULL AND auth_methods && ARRAY['oidc', 'saml']::text[];

UPDATE refresh_tokens SET revoked_at = now()
WHERE revoked_at IS NULL AND session_id IN (
    SELECT id FROM sessions WHERE auth_methods && ARRAY['oidc', 'saml']::text[]
);

ALTER TABLE sessions ADD CONSTRAINT sessions_sso_member_context CHECK (
    CASE WHEN auth_methods && ARRAY['oidc', 'saml']::text[]
        THEN sso_member_id IS NOT NULL OR revoked_at IS NOT NULL
        ELSE sso_member_id IS NULL
    END
);

CREATE INDEX sessions_sso_binding_idx ON sessions(user_id, sso_member_id)
WHERE sso_member_id IS NOT NULL;


ALTER TABLE sign_in_attempts ADD COLUMN target_space_id text;

-- Outstanding attempts did not preserve the requested Space.
UPDATE sign_in_attempts SET consumed_at = now()
WHERE consumed_at IS NULL AND expires_at > now();


ALTER TABLE sessions
    ADD COLUMN sso_connection_id text REFERENCES sso_connections(id),
    ADD CONSTRAINT sessions_sso_connection_requires_member
        CHECK (sso_connection_id IS NULL OR sso_member_id IS NOT NULL);


ALTER TABLE applications
    ADD COLUMN human_oidc_generation bigint NOT NULL DEFAULT 1 CHECK (human_oidc_generation > 0);

-- A client that is restored to an earlier configuration must not regain
-- access to requests, codes or UserInfo credentials issued before the change.
CREATE FUNCTION set_human_oidc_generation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.human_oidc_enabled, NEW.status, NEW.visibility, NEW.review_status,
        NEW.client_id, NEW.redirect_uris, NEW.client_secret_hash)
        IS DISTINCT FROM
       (OLD.human_oidc_enabled, OLD.status, OLD.visibility, OLD.review_status,
        OLD.client_id, OLD.redirect_uris, OLD.client_secret_hash) THEN
        NEW.human_oidc_generation := OLD.human_oidc_generation + 1;
    ELSE
        NEW.human_oidc_generation := OLD.human_oidc_generation;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER applications_human_oidc_generation
    BEFORE UPDATE ON applications FOR EACH ROW EXECUTE FUNCTION set_human_oidc_generation();

CREATE TABLE oidc_login_requests (
    id text PRIMARY KEY CHECK (left(id, 4) = 'lrq_'),
    request_hash bytea NOT NULL UNIQUE CHECK (octet_length(request_hash) = 32),
    application_id text NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    application_generation bigint NOT NULL CHECK (application_generation > 0),
    redirect_uri text NOT NULL CHECK (redirect_uri <> ''),
    scope text NOT NULL CHECK (scope <> ''),
    state text NOT NULL CHECK (state <> ''),
    nonce text NOT NULL CHECK (nonce <> ''),
    code_challenge text NOT NULL CHECK (length(code_challenge) = 43),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CHECK ((status = 'pending') = (consumed_at IS NULL))
);
CREATE INDEX oidc_login_requests_expiry_idx ON oidc_login_requests (expires_at);

CREATE TABLE oidc_login_codes (
    id text PRIMARY KEY CHECK (left(id, 4) = 'lcd_'),
    code_hash bytea NOT NULL UNIQUE CHECK (octet_length(code_hash) = 32),
    request_id text NOT NULL UNIQUE REFERENCES oidc_login_requests(id) ON DELETE CASCADE,
    application_id text NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    application_generation bigint NOT NULL CHECK (application_generation > 0),
    user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id text NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    redirect_uri text NOT NULL CHECK (redirect_uri <> ''),
    scope text NOT NULL CHECK (scope <> ''),
    nonce text NOT NULL CHECK (nonce <> ''),
    code_challenge text NOT NULL CHECK (length(code_challenge) = 43),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz
);
CREATE INDEX oidc_login_codes_expiry_idx ON oidc_login_codes (expires_at);


-- The redeemed code is the immutable link to the client generation,
-- approved scopes, subject and original session.
CREATE TABLE oidc_userinfo_tokens (
    code_id text PRIMARY KEY REFERENCES oidc_login_codes(id) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    expires_at timestamptz NOT NULL
);
CREATE INDEX oidc_userinfo_tokens_expiry_idx ON oidc_userinfo_tokens(expires_at);

CREATE VIEW oidc_active_login_sessions AS
SELECT s.id AS session_id, u.id AS user_id, u.email, u.email_verified_at,
       u.display_name, u.avatar_url, LEAST(s.expires_at, b.expires_at) AS expires_at
FROM sessions s
JOIN users u ON u.id = s.user_id
LEFT JOIN user_members b ON b.user_id = s.user_id AND b.member_id = s.member_id
LEFT JOIN members m ON m.id = s.member_id
WHERE s.revoked_at IS NULL AND s.expires_at > statement_timestamp()
  AND u.disabled_at IS NULL AND u.status = 'active'
  AND (s.member_id IS NULL OR (
      m.type = 'human' AND m.status = 'active'
      AND b.status = 'active' AND b.revoked_at IS NULL
      AND (b.expires_at IS NULL OR b.expires_at > statement_timestamp())
  ));


CREATE TABLE signing_keys (
    kid text PRIMARY KEY CHECK (kid ~ '^[0-9a-f]{16}$'),
    issuer text NOT NULL CHECK (issuer <> ''),
    private_key_ciphertext bytea NOT NULL CHECK (octet_length(private_key_ciphertext) > 28),
    status text NOT NULL CHECK (status IN ('next', 'active', 'retiring'))
);

CREATE UNIQUE INDEX signing_keys_current_status_idx
    ON signing_keys (status) WHERE status IN ('next', 'active');

REVOKE UPDATE, DELETE ON TABLE signing_keys FROM plystra_auth_app;
ALTER TABLE signing_keys ENABLE ROW LEVEL SECURITY;
CREATE POLICY signing_keys_read ON signing_keys
    FOR SELECT TO plystra_auth_app USING (true);
CREATE POLICY signing_keys_bootstrap ON signing_keys
    FOR INSERT TO plystra_auth_app WITH CHECK (status = 'active');

-- Publisher-managed secrets follow a fixed authentication method. Keeping their
-- digests separate from the original client_secret_hash preserves outstanding
-- authorization codes when a publisher rotates its credential.
ALTER TABLE applications
    ADD COLUMN token_endpoint_auth_method text NOT NULL DEFAULT 'none'
        CHECK (token_endpoint_auth_method IN ('none', 'client_secret_basic')),
    ADD COLUMN oauth_client_secret_hash bytea,
    ADD COLUMN oauth_previous_secret_hash bytea,
    ADD COLUMN oauth_previous_secret_expires_at timestamptz,
    ADD CONSTRAINT applications_oauth_client_secrets CHECK (
        (token_endpoint_auth_method = 'none' AND oauth_client_secret_hash IS NULL AND oauth_previous_secret_hash IS NULL)
        OR (token_endpoint_auth_method = 'client_secret_basic' AND client_secret_hash IS NULL
            AND oauth_client_secret_hash IS NOT NULL AND octet_length(oauth_client_secret_hash) = 32
            AND jsonb_array_length(redirect_uris) > 0)
    ),
    ADD CONSTRAINT applications_prior_oauth_secret CHECK (
        (oauth_previous_secret_hash IS NULL) = (oauth_previous_secret_expires_at IS NULL)
        AND (oauth_previous_secret_hash IS NULL OR octet_length(oauth_previous_secret_hash) = 32)
    );


ALTER TABLE oidc_login_requests
    ADD COLUMN browser_bound boolean NOT NULL DEFAULT false,
    ADD COLUMN browser_attempt_id text REFERENCES sign_in_attempts(id) ON DELETE SET NULL,
    ADD COLUMN browser_session_id text REFERENCES sessions(id) ON DELETE SET NULL,
    ADD CONSTRAINT oidc_login_browser_context CHECK (
        browser_bound OR (browser_attempt_id IS NULL AND browser_session_id IS NULL)
    );


ALTER TABLE sso_states ADD COLUMN browser_bound boolean NOT NULL DEFAULT false;

ALTER TABLE oidc_login_requests
    ADD COLUMN browser_sso_state_id text REFERENCES sso_states(id) ON DELETE SET NULL,
    ADD CONSTRAINT oidc_login_browser_sso_context CHECK (
        browser_sso_state_id IS NULL OR (browser_bound AND browser_attempt_id IS NULL)
    );

CREATE UNIQUE INDEX oidc_login_browser_sso_state_idx ON oidc_login_requests (browser_sso_state_id)
    WHERE browser_sso_state_id IS NOT NULL;


ALTER TABLE sessions
    ADD COLUMN sso_auth_time timestamptz,
    ADD CONSTRAINT sessions_sso_auth_time_context CHECK (
        sso_auth_time IS NULL OR (sso_connection_id IS NOT NULL AND sso_auth_time <= auth_time)
    );


CREATE TABLE saml_browser_responses (
    state_id text PRIMARY KEY REFERENCES sso_states(id) ON DELETE CASCADE,
    ciphertext bytea NOT NULL,
    received_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CHECK (expires_at > received_at)
);

CREATE INDEX saml_browser_responses_expiry_idx ON saml_browser_responses(expires_at);

-- Store the configuring identity for each changed mapping. Entries without
-- an override retain the original connection configurator, including NULL.
ALTER TABLE sso_connections
    ADD COLUMN role_mapping_authority jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD CONSTRAINT sso_role_mapping_authority_object
        CHECK (jsonb_typeof(role_mapping_authority) = 'object');

ALTER TABLE sso_states
    ADD COLUMN link_session_id text REFERENCES sessions(id) ON DELETE CASCADE,
    ADD COLUMN link_member_id text REFERENCES members(id) ON DELETE CASCADE,
    ADD COLUMN link_connection_updated_at timestamptz,
    ADD CONSTRAINT sso_states_link_context_check CHECK (
        (link_session_id IS NULL AND link_member_id IS NULL AND link_connection_updated_at IS NULL)
        OR (link_session_id IS NOT NULL AND link_member_id IS NOT NULL
            AND link_connection_updated_at IS NOT NULL AND NOT browser_bound AND request_id IS NULL)
    );

CREATE INDEX sso_states_link_session_idx ON sso_states (link_session_id) WHERE link_session_id IS NOT NULL;
CREATE INDEX sso_states_link_member_idx ON sso_states (link_member_id) WHERE link_member_id IS NOT NULL;

CREATE INDEX directory_groups_active_name_idx
    ON directory_groups (directory_id, lower(display_name), id)
    WHERE deleted_at IS NULL;

CREATE TABLE saml_assertion_uses (
    connection_id text NOT NULL REFERENCES sso_connections(id) ON DELETE CASCADE,
    assertion_id_hash bytea NOT NULL CHECK (octet_length(assertion_id_hash) = 32),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (connection_id, assertion_id_hash)
);

CREATE INDEX saml_assertion_uses_expiry_idx ON saml_assertion_uses(expires_at);

ALTER TABLE directory_users ADD COLUMN scim_name jsonb NOT NULL DEFAULT '{}'
    CHECK (jsonb_typeof(scim_name) = 'object' AND octet_length(scim_name::text) <= 4096);

ALTER TABLE directory_users ADD COLUMN scim_emails jsonb NOT NULL DEFAULT '[]'
    CHECK (jsonb_typeof(scim_emails) = 'array' AND jsonb_array_length(scim_emails) <= 16);

ALTER TABLE sso_connections
    ADD COLUMN token_endpoint_auth_method text NOT NULL DEFAULT 'client_secret_basic'
    CHECK (token_endpoint_auth_method = 'client_secret_basic'
           OR (provider = 'oidc' AND token_endpoint_auth_method = 'client_secret_post'));

CREATE INDEX directory_group_members_member_idx
    ON directory_group_members (member_id, directory_group_id);
