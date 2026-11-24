-- +goose Up
ALTER TABLE sso_connections
    ADD COLUMN token_endpoint_auth_method text NOT NULL DEFAULT 'client_secret_basic'
    CHECK (token_endpoint_auth_method = 'client_secret_basic'
           OR (provider = 'oidc' AND token_endpoint_auth_method = 'client_secret_post'));

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
