-- +goose Up

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

-- +goose Down
-- Forward-only migrations: add a compensating migration if rollback is required.
