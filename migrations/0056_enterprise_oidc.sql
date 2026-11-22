-- +goose Up

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

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
