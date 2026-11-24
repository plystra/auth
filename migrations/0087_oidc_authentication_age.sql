-- +goose Up
ALTER TABLE oidc_login_requests
    ADD COLUMN max_authentication_age integer CHECK (max_authentication_age >= 0);

CREATE VIEW oidc_session_authentication_evidence AS
SELECT id AS session_id, auth_time AS session_authentication_time,
       (sso_connection_id IS NOT NULL) AS upstream,
       (CASE
         WHEN sso_connection_id IS NOT NULL THEN sso_auth_time
         WHEN auth_methods && ARRAY['oidc', 'saml']::text[] THEN NULL
         WHEN auth_methods && ARRAY['pwd', 'webauthn']::text[] THEN auth_time
       END)::timestamptz AS authentication_time
FROM sessions;

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
