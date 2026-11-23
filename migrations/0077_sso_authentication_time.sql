-- +goose Up

ALTER TABLE sessions
    ADD COLUMN sso_auth_time timestamptz,
    ADD CONSTRAINT sessions_sso_auth_time_context CHECK (
        sso_auth_time IS NULL OR (sso_connection_id IS NOT NULL AND sso_auth_time <= auth_time)
    );
