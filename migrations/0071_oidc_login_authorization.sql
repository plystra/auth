-- +goose Up

ALTER TABLE applications
    ADD COLUMN human_oidc_generation bigint NOT NULL DEFAULT 1 CHECK (human_oidc_generation > 0);

-- A client that is restored to an earlier configuration must not regain
-- access to requests, codes or UserInfo credentials issued before the change.
-- +goose StatementBegin
CREATE FUNCTION set_human_oidc_generation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.human_oidc_enabled, NEW.status, NEW.visibility, NEW.review_status,
        NEW.client_id, NEW.redirect_uris, NEW.client_secret_hash)
        IS DISTINCT FROM
       (OLD.human_oidc_enabled, OLD.status, OLD.visibility, OLD.review_status,
        OLD.client_id, OLD.redirect_uris, OLD.client_secret_hash) THEN
        NEW.human_oidc_generation := OLD.human_oidc_generation + 1;
    ELSE
        NEW.human_oidc_generation := OLD.human_oidc_generation;
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER applications_human_oidc_generation
    BEFORE UPDATE ON applications FOR EACH ROW EXECUTE FUNCTION set_human_oidc_generation();

CREATE TABLE oidc_login_requests (
    id text PRIMARY KEY CHECK (left(id, 4) = 'lrq_'),
    request_hash bytea NOT NULL UNIQUE CHECK (octet_length(request_hash) = 32),
    application_id text NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    application_generation bigint NOT NULL CHECK (application_generation > 0),
    redirect_uri text NOT NULL CHECK (redirect_uri <> ''),
    scope text NOT NULL CHECK (scope <> ''),
    state text NOT NULL CHECK (state <> ''),
    nonce text NOT NULL CHECK (nonce <> ''),
    code_challenge text NOT NULL CHECK (length(code_challenge) = 43),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CHECK ((status = 'pending') = (consumed_at IS NULL))
);
CREATE INDEX oidc_login_requests_expiry_idx ON oidc_login_requests (expires_at);

CREATE TABLE oidc_login_codes (
    id text PRIMARY KEY CHECK (left(id, 4) = 'lcd_'),
    code_hash bytea NOT NULL UNIQUE CHECK (octet_length(code_hash) = 32),
    request_id text NOT NULL UNIQUE REFERENCES oidc_login_requests(id) ON DELETE CASCADE,
    application_id text NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    application_generation bigint NOT NULL CHECK (application_generation > 0),
    user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id text NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    redirect_uri text NOT NULL CHECK (redirect_uri <> ''),
    scope text NOT NULL CHECK (scope <> ''),
    nonce text NOT NULL CHECK (nonce <> ''),
    code_challenge text NOT NULL CHECK (length(code_challenge) = 43),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz
);
CREATE INDEX oidc_login_codes_expiry_idx ON oidc_login_codes (expires_at);

-- +goose Down
-- Forward-only migration.
