-- +goose Up

CREATE TABLE passkey_challenges (
    id text PRIMARY KEY CHECK (id LIKE 'pch_%'),
    user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id text NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    name text NOT NULL,
    session_data jsonb NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX passkey_challenges_active_idx ON passkey_challenges (user_id, expires_at)
    WHERE consumed_at IS NULL;

CREATE UNIQUE INDEX factors_webauthn_credential_id_idx ON factors (credential_id)
    WHERE kind = 'webauthn';

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
