-- +goose Up

ALTER TABLE authorization_grants
    ALTER COLUMN role_id DROP NOT NULL,
    ADD COLUMN IF NOT EXISTS permission_keys jsonb;

ALTER TABLE authorization_grants
    DROP CONSTRAINT IF EXISTS authorization_grants_source_check;
ALTER TABLE authorization_grants
    ADD CONSTRAINT authorization_grants_source_check CHECK (
        (role_id IS NOT NULL AND permission_keys IS NULL)
        OR (role_id IS NULL AND jsonb_typeof(permission_keys) = 'array' AND jsonb_array_length(permission_keys) > 0)
    );

CREATE INDEX IF NOT EXISTS authorization_grants_inline_idx
    ON authorization_grants USING gin (permission_keys)
    WHERE permission_keys IS NOT NULL AND revoked_at IS NULL;

-- +goose Down
-- Forward-only migration: replace this migration with a compensating one.
