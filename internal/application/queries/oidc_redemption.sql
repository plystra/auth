-- name: GetOIDCCodeSession :one
SELECT c.id, c.user_id, c.session_id, s.member_id
FROM oidc_login_codes c
JOIN sessions s ON s.id = c.session_id AND s.user_id = c.user_id
WHERE c.application_id = sqlc.arg(application_id) AND c.code_hash = sqlc.arg(code_hash)
  AND c.redirect_uri = sqlc.arg(redirect_uri) AND c.consumed_at IS NULL
  AND c.expires_at > statement_timestamp();

-- name: ConsumeOIDCLoginCode :one
UPDATE oidc_login_codes c SET consumed_at = statement_timestamp()
FROM applications a, oidc_active_login_sessions s
WHERE c.id = sqlc.arg(code_id) AND c.consumed_at IS NULL AND c.expires_at > statement_timestamp()
  AND c.code_challenge = sqlc.arg(code_challenge)
  AND a.id = c.application_id AND a.human_oidc_enabled AND a.status = 'active'
  AND (a.visibility <> 'public' OR a.review_status = 'approved')
  AND c.application_generation = a.human_oidc_generation
  AND s.session_id = c.session_id AND s.user_id = c.user_id
RETURNING c.id, c.user_id, c.nonce, c.scope, c.expires_at, s.expires_at::timestamptz AS session_expires_at;

-- name: CreateOIDCUserInfoToken :exec
INSERT INTO oidc_userinfo_tokens (code_id, token_hash, expires_at)
VALUES (sqlc.arg(code_id), sqlc.arg(token_hash), sqlc.arg(expires_at));

-- name: GetOIDCUserInfo :one
SELECT c.user_id, c.scope, s.email, s.email_verified_at, s.display_name, s.avatar_url
FROM oidc_userinfo_tokens t
JOIN oidc_login_codes c ON c.id = t.code_id
JOIN applications a ON a.id = c.application_id AND a.human_oidc_generation = c.application_generation
JOIN oidc_active_login_sessions s ON s.session_id = c.session_id AND s.user_id = c.user_id
WHERE t.token_hash = sqlc.arg(token_hash) AND t.expires_at > statement_timestamp()
  AND a.human_oidc_enabled AND a.status = 'active'
  AND (a.visibility <> 'public' OR a.review_status = 'approved');

-- name: GetOIDCUserInfoApplication :one
SELECT c.application_id FROM oidc_userinfo_tokens t JOIN oidc_login_codes c ON c.id = t.code_id
WHERE t.token_hash = sqlc.arg(token_hash);

-- name: RevokeOIDCUserInfoForApplication :exec
DELETE FROM oidc_userinfo_tokens t USING oidc_login_codes c
WHERE t.code_id = c.id AND c.application_id = sqlc.arg(application_id) AND t.token_hash = sqlc.arg(token_hash);
