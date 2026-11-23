-- +goose Up

ALTER TABLE sso_states ADD COLUMN browser_bound boolean NOT NULL DEFAULT false;

ALTER TABLE oidc_login_requests
    ADD COLUMN browser_sso_state_id text REFERENCES sso_states(id) ON DELETE SET NULL,
    ADD CONSTRAINT oidc_login_browser_sso_context CHECK (
        browser_sso_state_id IS NULL OR (browser_bound AND browser_attempt_id IS NULL)
    );

CREATE UNIQUE INDEX oidc_login_browser_sso_state_idx ON oidc_login_requests (browser_sso_state_id)
    WHERE browser_sso_state_id IS NOT NULL;
