-- +goose Up
ALTER TABLE directory_users ADD COLUMN scim_emails jsonb NOT NULL DEFAULT '[]'
    CHECK (jsonb_typeof(scim_emails) = 'array' AND jsonb_array_length(scim_emails) <= 16);

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
