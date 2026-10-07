-- +goose Up

CREATE TABLE sign_in_attempts (
    id text PRIMARY KEY CHECK (id LIKE 'sia_%'),
    user_id text REFERENCES users(id) ON DELETE SET NULL,
    email_normalized text NOT NULL,
    ip text,
    user_agent text,
    failed_attempts integer NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    locked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX sign_in_attempts_active_idx
    ON sign_in_attempts (expires_at)
    WHERE consumed_at IS NULL AND locked_at IS NULL;

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
