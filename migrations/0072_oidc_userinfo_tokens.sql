-- +goose Up

-- The redeemed code is the immutable link to the client generation,
-- approved scopes, subject and original session.
CREATE TABLE oidc_userinfo_tokens (
    code_id text PRIMARY KEY REFERENCES oidc_login_codes(id) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    expires_at timestamptz NOT NULL
);
CREATE INDEX oidc_userinfo_tokens_expiry_idx ON oidc_userinfo_tokens(expires_at);

CREATE VIEW oidc_active_login_sessions AS
SELECT s.id AS session_id, u.id AS user_id, u.email, u.email_verified_at,
       u.display_name, u.avatar_url, LEAST(s.expires_at, b.expires_at) AS expires_at
FROM sessions s
JOIN users u ON u.id = s.user_id
LEFT JOIN user_members b ON b.user_id = s.user_id AND b.member_id = s.member_id
LEFT JOIN members m ON m.id = s.member_id
WHERE s.revoked_at IS NULL AND s.expires_at > statement_timestamp()
  AND u.disabled_at IS NULL AND u.status = 'active'
  AND (s.member_id IS NULL OR (
      m.type = 'human' AND m.status = 'active'
      AND b.status = 'active' AND b.revoked_at IS NULL
      AND (b.expires_at IS NULL OR b.expires_at > statement_timestamp())
  ));
