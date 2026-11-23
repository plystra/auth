-- name: GetSAMLBrowserRelay :one
SELECT s.id, s.request_id, s.expires_at, r.id AS interaction_id
FROM sso_states s
JOIN oidc_login_requests r ON r.browser_sso_state_id = s.id
JOIN applications a ON a.id = r.application_id
JOIN sso_connections c ON c.id = s.connection_id
WHERE s.state_hash = sqlc.arg(state_hash) AND s.connection_id = sqlc.arg(connection_id)
  AND s.redirect_uri = sqlc.arg(redirect_uri) AND s.browser_bound AND s.request_id IS NOT NULL
  AND s.consumed_at IS NULL AND s.expires_at > clock_timestamp()
  AND c.provider = 'saml' AND c.status = 'active' AND c.redirect_uri = s.redirect_uri
  AND r.status = 'pending' AND r.expires_at > clock_timestamp() AND r.browser_session_id IS NULL
  AND a.human_oidc_enabled AND a.human_oidc_generation = r.application_generation
  AND a.status = 'active' AND (a.visibility <> 'public' OR a.review_status = 'approved');

-- name: InsertSAMLBrowserResponse :execrows
INSERT INTO saml_browser_responses (state_id, ciphertext, received_at, expires_at)
SELECT s.id, sqlc.arg(ciphertext), sqlc.arg(received_at), s.expires_at
FROM sso_states s
WHERE s.id = sqlc.arg(state_id) AND s.consumed_at IS NULL
  AND s.expires_at > clock_timestamp() AND s.expires_at > sqlc.arg(received_at)
FOR UPDATE OF s
ON CONFLICT (state_id) DO NOTHING;

-- name: GetSAMLBrowserResponse :one
SELECT s.id, s.state_hash, s.request_id, p.ciphertext, p.received_at
FROM oidc_login_requests r
JOIN applications a ON a.id = r.application_id
JOIN sso_states s ON s.id = r.browser_sso_state_id
JOIN saml_browser_responses p ON p.state_id = s.id
WHERE r.id = sqlc.arg(interaction_id) AND r.request_hash = sqlc.arg(request_hash)
  AND r.browser_bound AND r.status = 'pending' AND r.browser_session_id IS NULL
  AND r.expires_at > clock_timestamp() AND p.expires_at > clock_timestamp()
  AND s.connection_id = sqlc.arg(connection_id) AND s.redirect_uri = sqlc.arg(redirect_uri)
  AND s.browser_bound AND s.consumed_at IS NULL AND s.expires_at > clock_timestamp()
  AND a.human_oidc_enabled AND a.human_oidc_generation = r.application_generation
  AND a.status = 'active' AND (a.visibility <> 'public' OR a.review_status = 'approved');

-- name: DeleteSAMLBrowserResponse :exec
DELETE FROM saml_browser_responses WHERE state_id = sqlc.arg(state_id);

-- name: DeleteExpiredSAMLBrowserResponses :execrows
DELETE FROM saml_browser_responses
WHERE state_id IN (
    SELECT state_id FROM saml_browser_responses
    WHERE expires_at <= statement_timestamp() ORDER BY expires_at LIMIT 1000
    FOR UPDATE SKIP LOCKED
);
