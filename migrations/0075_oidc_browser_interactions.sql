-- +goose Up

ALTER TABLE oidc_login_requests
    ADD COLUMN browser_bound boolean NOT NULL DEFAULT false,
    ADD COLUMN browser_attempt_id text REFERENCES sign_in_attempts(id) ON DELETE SET NULL,
    ADD COLUMN browser_session_id text REFERENCES sessions(id) ON DELETE SET NULL,
    ADD CONSTRAINT oidc_login_browser_context CHECK (
        browser_bound OR (browser_attempt_id IS NULL AND browser_session_id IS NULL)
    );
