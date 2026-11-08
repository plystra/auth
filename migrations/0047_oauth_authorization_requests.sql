-- +goose Up

-- Keep the pre-consent request separate from authorization codes. The public
-- request handle is never stored; only its SHA-256 digest can locate the row.
CREATE TABLE oauth_authorization_requests (
    id text PRIMARY KEY CHECK (left(id, 4) = 'arq_'),
    request_hash bytea NOT NULL UNIQUE CHECK (length(request_hash) = 32),
    application_id text NOT NULL REFERENCES applications(id),
    redirect_uri text NOT NULL CHECK (redirect_uri <> ''),
    code_challenge text NOT NULL CHECK (code_challenge <> ''),
    scope text NOT NULL CHECK (scope <> ''),
    state text NOT NULL CHECK (state <> ''),
    nonce text NOT NULL CHECK (nonce <> ''),
    resource text NOT NULL CHECK (resource <> ''),
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'denied')),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((status = 'pending' AND consumed_at IS NULL)
        OR (status <> 'pending' AND consumed_at IS NOT NULL))
);

CREATE INDEX oauth_authorization_requests_pending_expiry_idx
    ON oauth_authorization_requests (expires_at)
    WHERE status = 'pending';

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
