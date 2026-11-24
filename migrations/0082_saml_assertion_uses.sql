-- +goose Up
CREATE TABLE saml_assertion_uses (
    connection_id text NOT NULL REFERENCES sso_connections(id) ON DELETE CASCADE,
    assertion_id_hash bytea NOT NULL CHECK (octet_length(assertion_id_hash) = 32),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (connection_id, assertion_id_hash)
);

CREATE INDEX saml_assertion_uses_expiry_idx ON saml_assertion_uses(expires_at);

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
