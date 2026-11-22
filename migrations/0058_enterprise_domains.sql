-- +goose Up

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

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
