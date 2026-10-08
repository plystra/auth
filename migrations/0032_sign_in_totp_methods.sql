-- +goose Up

ALTER TABLE sign_in_attempts ADD COLUMN password_verified_at timestamptz;

ALTER TABLE sessions
    ADD COLUMN auth_methods text[] NOT NULL DEFAULT ARRAY['pwd']::text[],
    ADD CONSTRAINT sessions_auth_methods_nonempty CHECK (cardinality(auth_methods) > 0);

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
