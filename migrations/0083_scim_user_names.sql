-- +goose Up
ALTER TABLE directory_users ADD COLUMN scim_name jsonb NOT NULL DEFAULT '{}'
    CHECK (jsonb_typeof(scim_name) = 'object' AND octet_length(scim_name::text) <= 4096);

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
