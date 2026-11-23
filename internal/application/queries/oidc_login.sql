-- name: CreateOIDCLoginRequest :one
INSERT INTO oidc_login_requests (
    id, request_hash, application_id, application_generation, redirect_uri, scope,
    state, nonce, code_challenge, expires_at
) VALUES (
    sqlc.arg(id), sqlc.arg(request_hash), sqlc.arg(application_id), sqlc.arg(application_generation),
    sqlc.arg(redirect_uri), sqlc.arg(scope), sqlc.arg(state), sqlc.arg(nonce),
    sqlc.arg(code_challenge), clock_timestamp() + interval '5 minutes'
) RETURNING expires_at;

-- name: FindOIDCLoginRequestClient :one
SELECT application_id FROM oidc_login_requests
WHERE request_hash = sqlc.arg(request_hash) AND status = 'pending' AND expires_at > clock_timestamp();

-- name: FinishOIDCLoginRequest :one
UPDATE oidc_login_requests SET status = sqlc.arg(status), consumed_at = clock_timestamp()
WHERE request_hash = sqlc.arg(request_hash) AND application_id = sqlc.arg(application_id)
    AND application_generation = sqlc.arg(application_generation)
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
