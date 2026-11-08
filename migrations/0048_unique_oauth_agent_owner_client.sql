-- +goose Up

-- A live OAuth authorization has exactly one Agent for each owner and client.
-- If an older deployment contains duplicates, migration must stop for an
-- explicit reconciliation rather than silently discard grants or credentials.
CREATE UNIQUE INDEX members_oauth_owner_client_unique
    ON members (created_by_member_id, oauth_client_id)
    WHERE type = 'agent' AND source = 'oauth' AND status <> 'removed';

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
