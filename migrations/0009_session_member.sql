-- +goose Up

ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS member_id text REFERENCES members(id);

CREATE INDEX IF NOT EXISTS sessions_member_idx ON sessions(member_id);

-- +goose Down
-- Forward-only migration: replace this migration with a compensating migration.
