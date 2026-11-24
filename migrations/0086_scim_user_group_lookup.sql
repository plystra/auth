-- +goose Up
CREATE INDEX directory_group_members_member_idx
    ON directory_group_members (member_id, directory_group_id);

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
