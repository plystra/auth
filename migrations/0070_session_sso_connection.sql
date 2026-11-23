-- +goose Up

ALTER TABLE sessions
    ADD COLUMN sso_connection_id text REFERENCES sso_connections(id),
    ADD CONSTRAINT sessions_sso_connection_requires_member
        CHECK (sso_connection_id IS NULL OR sso_member_id IS NOT NULL);
