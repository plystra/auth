-- +goose Up
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

-- +goose Down
-- Forward-only migration.
