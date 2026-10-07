-- +goose Up

ALTER TABLE factors ADD COLUMN IF NOT EXISTS secret_hash bytea;

ALTER TABLE factors DROP CONSTRAINT IF EXISTS factors_backup_code_storage_check;
ALTER TABLE factors ADD CONSTRAINT factors_backup_code_storage_check CHECK (
    (kind = 'backup_code' AND secret_hash IS NOT NULL AND secret_ciphertext IS NULL)
    OR kind <> 'backup_code'
);

-- +goose Down
-- Forward-only migration: replace this migration with a compensating migration.
