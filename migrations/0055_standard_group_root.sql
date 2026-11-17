-- +goose Up

-- A suspended standard root still owns its place in the Space tree. Removed
-- roots are tombstones; Agent-owned trees have their own ownership constraints.
-- Existing duplicate live roots make this migration fail without changing
-- their identities, grants, memberships, or parent relationships.
CREATE UNIQUE INDEX groups_standard_root_unique ON groups (space_id)
    WHERE kind = 'standard' AND parent_id IS NULL AND status <> 'removed';

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
