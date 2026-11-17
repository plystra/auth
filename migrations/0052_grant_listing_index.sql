-- +goose Up

-- Grant configuration is filtered by Space and traversed in creation order.
-- Keep revoked tombstones out of the listing index without deleting history.
CREATE INDEX authorization_grants_space_listing_idx
    ON authorization_grants(space_id, created_at DESC, id DESC)
    WHERE revoked_at IS NULL;

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
