
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
