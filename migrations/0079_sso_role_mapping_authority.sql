-- +goose Up
-- Store the configuring identity for each changed mapping. Entries without
-- an override retain the original connection configurator, including NULL.
ALTER TABLE sso_connections
    ADD COLUMN role_mapping_authority jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD CONSTRAINT sso_role_mapping_authority_object
        CHECK (jsonb_typeof(role_mapping_authority) = 'object');

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
