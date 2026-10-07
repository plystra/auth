-- +goose Up

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS password_reset_required_at timestamptz;

-- +goose Down
-- Forward-only migrations: add a compensating migration if rollback is required.
