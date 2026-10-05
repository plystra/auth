-- name: GetAPIKeyByPrefix :one
SELECT k.id, k.application_id, k.name, k.prefix, k.secret_hash, k.scopes, k.expires_at, k.last_used_at, k.revoked_at, k.created_at, a.space_id, a.name AS application_name FROM api_keys k JOIN applications a ON a.id = k.application_id WHERE k.prefix = sqlc.arg(prefix) LIMIT 1;

-- name: TouchAPIKey :exec
UPDATE api_keys SET last_used_at = now() WHERE id = sqlc.arg(id);

-- name: CreateApplication :one
INSERT INTO applications (id, space_id, name, redirect_uris, allowed_scopes, client_id, client_secret_hash) VALUES (sqlc.arg(id), sqlc.arg(space_id), sqlc.arg(name), COALESCE(sqlc.narg(redirect_uris), '[]'::jsonb), COALESCE(sqlc.narg(allowed_scopes), '[]'::jsonb), sqlc.arg(client_id), sqlc.narg(client_secret_hash)) RETURNING id, space_id, name, redirect_uris, allowed_scopes, client_id, client_secret_hash, created_at;

-- name: CreateAPIKey :one
INSERT INTO api_keys (id, application_id, name, prefix, secret_hash, scopes, expires_at) VALUES (sqlc.arg(id), sqlc.arg(application_id), sqlc.arg(name), sqlc.arg(prefix), sqlc.arg(secret_hash), COALESCE(sqlc.narg(scopes), '[]'::jsonb), sqlc.narg(expires_at)) RETURNING id, application_id, name, prefix, secret_hash, scopes, expires_at, last_used_at, revoked_at, created_at;
