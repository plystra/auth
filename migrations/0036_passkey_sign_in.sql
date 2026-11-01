-- +goose Up

ALTER TABLE sign_in_attempts
    ADD COLUMN method text NOT NULL DEFAULT 'password' CHECK (method IN ('password', 'passkey')),
    ADD COLUMN passkey_session jsonb;

ALTER TABLE sign_in_attempts
    ADD CONSTRAINT sign_in_attempts_passkey_session_check
    CHECK ((method = 'passkey') = (passkey_session IS NOT NULL));

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
