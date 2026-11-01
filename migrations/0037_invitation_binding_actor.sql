-- +goose Up

ALTER TABLE invitation_tokens
    ADD COLUMN inviter_member_id text REFERENCES members(id) ON DELETE SET NULL,
    ADD COLUMN inviter_user_id text REFERENCES users(id) ON DELETE SET NULL;

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
