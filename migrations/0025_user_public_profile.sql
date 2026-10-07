-- +goose Up

ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name text NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url text NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS public_metadata jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE users ADD COLUMN IF NOT EXISTS private_metadata jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE users ADD CONSTRAINT users_public_metadata_object_check
    CHECK (jsonb_typeof(public_metadata) = 'object');
ALTER TABLE users ADD CONSTRAINT users_private_metadata_object_check
    CHECK (jsonb_typeof(private_metadata) = 'object');

-- +goose Down
-- Forward-only migration: replace this migration with a compensating migration.
