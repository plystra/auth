-- +goose Up
-- JIT role mappings use the configuring identity's current assignment rights.
-- Older connections keep their data and have no inferred configurator.
ALTER TABLE sso_connections
    ADD COLUMN configured_by_member_id text REFERENCES members(id),
    ADD COLUMN configured_by_user_id text REFERENCES users(id),
    ADD CONSTRAINT sso_configurator_user_requires_member
        CHECK (configured_by_user_id IS NULL OR configured_by_member_id IS NOT NULL);

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
