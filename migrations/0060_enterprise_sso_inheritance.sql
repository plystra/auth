-- +goose Up

ALTER TABLE sso_connections
    ADD COLUMN IF NOT EXISTS covers_subtree boolean NOT NULL DEFAULT false;

ALTER TABLE sso_domains
    ADD COLUMN IF NOT EXISTS covers_subtree boolean NOT NULL DEFAULT false;

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
