-- +goose Up

-- Existing SHA-256 digests are wrapped with the deployment HMAC key by the
-- service before it accepts requests. New keys are HMAC-protected at creation.
-- Stop the old binary before applying this migration: it cannot authenticate
-- converted keys and would label newly inserted SHA-256 hashes as HMAC hashes.
ALTER TABLE api_keys
    ADD COLUMN hash_scheme text NOT NULL DEFAULT 'sha256_legacy'
        CHECK (hash_scheme IN ('sha256_legacy', 'hmac_sha256'));

ALTER TABLE api_keys ALTER COLUMN hash_scheme SET DEFAULT 'hmac_sha256';

-- +goose Down
-- Forward-only migrations: add a compensating migration if rollback is required.
