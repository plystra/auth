-- name: GetAPIKeyByPrefix :one
SELECT k.id, k.application_id, k.name, k.prefix, k.secret_hash, k.scopes, k.expires_at, k.last_used_at, k.revoked_at, k.created_at, k.allow_subject_assertion, a.space_id, a.name AS application_name, a.client_id FROM api_keys k JOIN applications a ON a.id = k.application_id WHERE k.prefix = sqlc.arg(prefix) LIMIT 1;

-- name: TouchAPIKey :exec
UPDATE api_keys SET last_used_at = now() WHERE id = sqlc.arg(id);

-- name: CreateApplication :one
INSERT INTO applications (id, space_id, name, redirect_uris, allowed_scopes, client_id, client_secret_hash, manifest_permissions)
VALUES (sqlc.arg(id), sqlc.arg(space_id), sqlc.arg(name), COALESCE(sqlc.narg(redirect_uris), '[]'::jsonb), COALESCE(sqlc.narg(allowed_scopes), '[]'::jsonb), sqlc.arg(client_id), sqlc.narg(client_secret_hash), sqlc.arg(manifest_permissions))
RETURNING id, space_id, name, redirect_uris, allowed_scopes, client_id, client_secret_hash, manifest_permissions, visibility, status, created_at;

-- name: ListPublishedApplications :many
SELECT id, space_id, name, client_id, redirect_uris, manifest_permissions, visibility, status, created_at
FROM applications
WHERE space_id = sqlc.arg(space_id)
ORDER BY created_at, id;

-- name: GetApplicationByClientID :one
SELECT id, space_id, name, redirect_uris, allowed_scopes, client_id, client_secret_hash, created_at
FROM applications
WHERE client_id = sqlc.arg(client_id)
LIMIT 1;

-- name: CreateAuthorizationCode :exec
INSERT INTO authorization_codes (
    id, application_id, user_id, member_id, redirect_uri, code_hash,
    code_challenge, code_challenge_method, scope, nonce, resource, expires_at
)
VALUES (
    sqlc.arg(id), sqlc.arg(application_id), sqlc.arg(user_id), sqlc.narg(member_id),
    sqlc.arg(redirect_uri), sqlc.arg(code_hash), sqlc.arg(code_challenge),
    sqlc.arg(code_challenge_method), sqlc.arg(scope), sqlc.narg(nonce),
    sqlc.narg(resource), sqlc.arg(expires_at)
);

-- name: ConsumeAuthorizationCode :one
UPDATE authorization_codes
SET consumed_at = now()
WHERE code_hash = sqlc.arg(code_hash)
  AND application_id = sqlc.arg(application_id)
  AND redirect_uri = sqlc.arg(redirect_uri)
  AND consumed_at IS NULL
  AND expires_at > now()
RETURNING id, application_id, user_id, member_id, redirect_uri, code_hash,
          code_challenge, code_challenge_method, scope, nonce, resource,
          expires_at, consumed_at;

-- name: CreateAPIKey :one
INSERT INTO api_keys (id, application_id, name, prefix, secret_hash, scopes, expires_at, allow_subject_assertion) VALUES (sqlc.arg(id), sqlc.arg(application_id), sqlc.arg(name), sqlc.arg(prefix), sqlc.arg(secret_hash), COALESCE(sqlc.narg(scopes), '[]'::jsonb), sqlc.narg(expires_at), sqlc.arg(allow_subject_assertion)) RETURNING id, application_id, name, prefix, secret_hash, scopes, expires_at, last_used_at, revoked_at, created_at, allow_subject_assertion;
