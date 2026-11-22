-- +goose Up

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

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
