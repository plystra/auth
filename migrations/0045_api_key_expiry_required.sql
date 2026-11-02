-- +goose Up

-- Reject new keys without an expiry while allowing old rows with no expiry to
-- be revoked. NOT VALID avoids rewriting historical rows during deployment;
-- authentication rejects any remaining row whose expiry is NULL.
ALTER TABLE api_keys ADD CONSTRAINT api_keys_expiry_required
    CHECK (expires_at IS NOT NULL OR revoked_at IS NOT NULL) NOT VALID;

-- +goose Down
-- Forward-only migrations: add a compensating migration if rollback is required.
