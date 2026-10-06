-- +goose Up

ALTER TABLE spaces
    ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'active';

-- +goose StatementBegin
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'spaces_status_check'
          AND conrelid = 'spaces'::regclass
    ) THEN
        ALTER TABLE spaces
            ADD CONSTRAINT spaces_status_check
            CHECK (status IN ('active', 'suspended'));
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
-- Forward-only migration: use a compensating migration if rollback is required.
