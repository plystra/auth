
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
