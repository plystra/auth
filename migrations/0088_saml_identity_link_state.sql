-- +goose Up
ALTER TABLE sso_states
    DROP CONSTRAINT sso_states_link_context_check,
    ADD CONSTRAINT sso_states_link_context_check CHECK (
        (link_session_id IS NULL AND link_member_id IS NULL AND link_connection_updated_at IS NULL)
        OR (link_session_id IS NOT NULL AND link_member_id IS NOT NULL
            AND link_connection_updated_at IS NOT NULL AND NOT browser_bound)
    );

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
