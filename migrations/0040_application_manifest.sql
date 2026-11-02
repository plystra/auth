-- +goose Up

ALTER TABLE applications
    ADD COLUMN manifest_permissions jsonb NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(manifest_permissions) = 'array'),
    ADD COLUMN visibility text NOT NULL DEFAULT 'private'
        CHECK (visibility IN ('private', 'public')),
    ADD COLUMN status text NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended'));

-- +goose Down
-- Forward-only migrations: add a compensating migration if rollback is required.
