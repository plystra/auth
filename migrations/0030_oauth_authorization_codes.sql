-- +goose Up

-- OAuth authorization codes are opaque, short-lived credentials. Keep only a
-- digest in the database and bind the code to the consented Agent member,
-- client nonce, and resource indicator.
ALTER TABLE authorization_codes
    ADD COLUMN IF NOT EXISTS code_hash bytea,
    ADD COLUMN IF NOT EXISTS member_id text REFERENCES members(id),
    ADD COLUMN IF NOT EXISTS nonce text,
    ADD COLUMN IF NOT EXISTS resource text;

CREATE UNIQUE INDEX IF NOT EXISTS authorization_codes_hash_idx
    ON authorization_codes(code_hash)
    WHERE code_hash IS NOT NULL;

-- +goose Down
