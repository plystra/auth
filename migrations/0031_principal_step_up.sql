-- +goose Up

ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS step_up_operation text,
    ADD COLUMN IF NOT EXISTS step_up_digest bytea,
    ADD COLUMN IF NOT EXISTS step_up_expires_at timestamptz;

CREATE INDEX IF NOT EXISTS sessions_step_up_idx
    ON sessions(id, step_up_expires_at)
    WHERE step_up_operation IS NOT NULL;

-- +goose Down
-- Forward-only migration: replace this migration with a compensating migration.
