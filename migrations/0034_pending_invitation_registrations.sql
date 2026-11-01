-- +goose Up

CREATE TABLE pending_invitation_registrations (
    user_id text PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    invitation_id text NOT NULL UNIQUE REFERENCES invitation_tokens(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
