-- +goose Up
ALTER TABLE sso_states
    ADD COLUMN link_session_id text REFERENCES sessions(id) ON DELETE CASCADE,
    ADD COLUMN link_member_id text REFERENCES members(id) ON DELETE CASCADE,
    ADD COLUMN link_connection_updated_at timestamptz,
    ADD CONSTRAINT sso_states_link_context_check CHECK (
        (link_session_id IS NULL AND link_member_id IS NULL AND link_connection_updated_at IS NULL)
        OR (link_session_id IS NOT NULL AND link_member_id IS NOT NULL
            AND link_connection_updated_at IS NOT NULL AND NOT browser_bound AND request_id IS NULL)
    );

CREATE INDEX sso_states_link_session_idx ON sso_states (link_session_id) WHERE link_session_id IS NOT NULL;
CREATE INDEX sso_states_link_member_idx ON sso_states (link_member_id) WHERE link_member_id IS NOT NULL;

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
