-- +goose Up

ALTER TABLE permissions
    ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'active';

-- +goose StatementBegin
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'permissions_status_check'
          AND conrelid = 'permissions'::regclass
    ) THEN
        ALTER TABLE permissions
            ADD CONSTRAINT permissions_status_check
            CHECK (status IN ('active', 'deprecated', 'disabled'));
    END IF;
END $$;
-- +goose StatementEnd

UPDATE permissions
SET status = CASE WHEN enabled THEN 'active' ELSE 'disabled' END
WHERE status = 'active' AND enabled = false;

ALTER TABLE permissions DROP COLUMN IF EXISTS enabled;

-- +goose Down
-- Forward-only migration: replace this migration with a compensating migration.
