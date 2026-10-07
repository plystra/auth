-- +goose Up

CREATE TABLE invitation_tokens (
    id text PRIMARY KEY CHECK (id LIKE 'ivt_%'),
    space_id text NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    email_normalized text NOT NULL,
    member_id text REFERENCES members(id) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX invitation_tokens_active_idx
    ON invitation_tokens (space_id, email_normalized, expires_at)
    WHERE consumed_at IS NULL;

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
