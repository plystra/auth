
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

-- Forward-only migrations: restore from a PostgreSQL backup or add a compensating migration.






