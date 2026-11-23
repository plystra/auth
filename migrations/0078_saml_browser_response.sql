-- +goose Up

CREATE TABLE saml_browser_responses (
    state_id text PRIMARY KEY REFERENCES sso_states(id) ON DELETE CASCADE,
    ciphertext bytea NOT NULL,
    received_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CHECK (expires_at > received_at)
);

CREATE INDEX saml_browser_responses_expiry_idx ON saml_browser_responses(expires_at);
