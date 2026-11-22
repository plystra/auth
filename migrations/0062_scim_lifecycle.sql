-- +goose Up

-- Preserve deleted external identities permanently; deactivation is reversible,
-- deletion is not. Existing inactive resources remain deactivated, not deleted.
ALTER TABLE directory_users ADD COLUMN deleted_at timestamptz;
ALTER TABLE directory_users ADD CONSTRAINT directory_users_deleted_inactive
    CHECK (deleted_at IS NULL OR NOT active);
ALTER TABLE directory_groups ADD COLUMN deleted_at timestamptz;

-- Legacy directories have no trustworthy configurator. Positive authority
-- changes fail closed until an authenticated administrator rotates the token.
ALTER TABLE directories ADD COLUMN configured_by_member_id text REFERENCES members(id);
ALTER TABLE directories ADD COLUMN configured_by_user_id text REFERENCES users(id);

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
