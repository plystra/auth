-- name: CreateOIDCLoginRequest :one
INSERT INTO oidc_login_requests (
    id, request_hash, application_id, application_generation, redirect_uri, scope,
    state, nonce, code_challenge, browser_bound, expires_at
) VALUES (
    sqlc.arg(id), sqlc.arg(request_hash), sqlc.arg(application_id), sqlc.arg(application_generation),
    sqlc.arg(redirect_uri), sqlc.arg(scope), sqlc.arg(state), sqlc.arg(nonce),
    sqlc.arg(code_challenge), sqlc.arg(browser_bound), clock_timestamp() + interval '5 minutes'
) RETURNING expires_at;

-- name: FindOIDCLoginRequestClient :one
SELECT application_id FROM oidc_login_requests
WHERE request_hash = sqlc.arg(request_hash) AND browser_bound = sqlc.arg(browser_bound)
  AND status = 'pending' AND expires_at > clock_timestamp();

-- name: BindOIDCAuthorizationToBrowser :one
UPDATE oidc_login_requests SET browser_bound = true, request_hash = sqlc.arg(cookie_hash)
WHERE request_hash = sqlc.arg(authorization_hash) AND NOT browser_bound
    AND status = 'pending' AND expires_at > clock_timestamp()
    AND application_id = sqlc.arg(application_id)
    AND application_generation = sqlc.arg(application_generation)
RETURNING id, redirect_uri, scope, expires_at;

-- name: FinishOIDCLoginRequest :one
UPDATE oidc_login_requests SET status = sqlc.arg(status), consumed_at = clock_timestamp()
WHERE request_hash = sqlc.arg(request_hash) AND application_id = sqlc.arg(application_id)
    AND application_generation = sqlc.arg(application_generation)
    AND browser_bound = sqlc.arg(browser_bound)
    AND status = 'pending' AND expires_at > clock_timestamp()
RETURNING id, redirect_uri, state, scope, expires_at;

-- name: IssueOIDCLoginCode :execrows
INSERT INTO oidc_login_codes (
    id, code_hash, request_id, application_id, application_generation, user_id, session_id,
    redirect_uri, scope, nonce, code_challenge, expires_at
)
SELECT sqlc.arg(id), sqlc.arg(code_hash), r.id, r.application_id, r.application_generation,
       sqlc.arg(user_id), sqlc.arg(session_id), r.redirect_uri, r.scope, r.nonce, r.code_challenge,
       clock_timestamp() + interval '2 minutes'
FROM oidc_login_requests r
WHERE r.id = sqlc.arg(request_id) AND r.status = 'approved' AND r.expires_at > clock_timestamp();

-- name: GetPendingOIDCBrowserInteraction :one
SELECT r.id, r.application_id, a.name AS client_name, a.client_id, r.scope, r.expires_at,
    r.browser_attempt_id, r.browser_session_id,
    COALESCE(sso.connection_id, '')::text AS sso_connection_id,
    COALESCE(attempt.method, '')::text AS sign_in_method,
    (attempt.password_verified_at IS NOT NULL)::boolean AS needs_totp
FROM oidc_login_requests r
JOIN applications a ON a.id = r.application_id
LEFT JOIN sign_in_attempts attempt ON attempt.id = r.browser_attempt_id
LEFT JOIN sso_states sso ON sso.id = r.browser_sso_state_id
WHERE r.id = sqlc.arg(id) AND r.request_hash = sqlc.arg(request_hash)
    AND r.browser_bound AND r.status = 'pending' AND r.expires_at > clock_timestamp()
    AND a.human_oidc_enabled AND a.human_oidc_generation = r.application_generation
    AND a.status = 'active' AND (a.visibility <> 'public' OR a.review_status = 'approved');

-- name: SetOIDCBrowserAttempt :execrows
UPDATE oidc_login_requests r SET browser_attempt_id = sqlc.arg(attempt_id)::text
FROM applications a
WHERE r.id = sqlc.arg(id) AND r.request_hash = sqlc.arg(request_hash)
    AND r.browser_bound AND r.status = 'pending' AND r.expires_at > clock_timestamp()
    AND r.browser_attempt_id IS NULL AND r.browser_session_id IS NULL AND r.browser_sso_state_id IS NULL
    AND a.id = r.application_id AND a.human_oidc_generation = r.application_generation;

-- name: BindOIDCBrowserSession :execrows
UPDATE oidc_login_requests r SET browser_session_id = sqlc.arg(session_id)::text
FROM applications a
WHERE r.id = sqlc.arg(id) AND r.request_hash = sqlc.arg(request_hash)
    AND r.browser_bound AND r.status = 'pending' AND r.expires_at > clock_timestamp()
    AND r.browser_attempt_id = sqlc.arg(attempt_id)::text AND r.browser_session_id IS NULL
    AND a.id = r.application_id AND a.human_oidc_generation = r.application_generation;
