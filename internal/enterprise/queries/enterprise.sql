-- name: CreateSSOConnection :one
INSERT INTO sso_connections (
    id, space_id, name, provider, issuer, client_id, client_secret_ciphertext,
    redirect_uri, groups_claim, role_mappings, status
)
VALUES (
    sqlc.arg(id), sqlc.arg(space_id), sqlc.arg(name), sqlc.arg(provider),
    sqlc.arg(issuer), sqlc.arg(client_id), sqlc.arg(client_secret_ciphertext),
    sqlc.arg(redirect_uri), sqlc.arg(groups_claim), sqlc.arg(role_mappings), 'active'
)
RETURNING id, space_id, name, provider, issuer, client_id, redirect_uri, groups_claim,
    role_mappings, status, created_at, updated_at;

-- name: GetSSOConnection :one
SELECT id, space_id, name, provider, issuer, client_id, client_secret_ciphertext,
    redirect_uri, groups_claim, role_mappings, status, created_at, updated_at
FROM sso_connections WHERE id = sqlc.arg(id);

-- name: ListSSOConnections :many
SELECT id, space_id, name, provider, issuer, client_id, redirect_uri, groups_claim,
    role_mappings, status, created_at, updated_at
FROM sso_connections WHERE space_id = sqlc.arg(space_id)
ORDER BY created_at, id;

-- name: LockSSOConnection :one
SELECT id, space_id, name, provider, issuer, client_id, client_secret_ciphertext,
    redirect_uri, groups_claim, role_mappings, status, created_at, updated_at
FROM sso_connections WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: DisableSSOConnection :exec
UPDATE sso_connections SET status = 'disabled', updated_at = now()
WHERE id = sqlc.arg(id) AND status <> 'disabled';

-- name: CreateSSOState :one
INSERT INTO sso_states (
    id, connection_id, state_hash, nonce_hash, pkce_verifier_ciphertext,
    redirect_uri, expires_at
)
VALUES (
    sqlc.arg(id), sqlc.arg(connection_id), sqlc.arg(state_hash), sqlc.arg(nonce_hash),
    sqlc.arg(pkce_verifier_ciphertext), sqlc.arg(redirect_uri), sqlc.arg(expires_at)
)
RETURNING id, connection_id, state_hash, nonce_hash, pkce_verifier_ciphertext,
    redirect_uri, expires_at, consumed_at, created_at;

-- name: LockSSOStateByHash :one
SELECT id, connection_id, state_hash, nonce_hash, pkce_verifier_ciphertext,
    redirect_uri, expires_at, consumed_at, created_at
FROM sso_states WHERE state_hash = sqlc.arg(state_hash) FOR UPDATE;

-- name: ConsumeSSOState :exec
UPDATE sso_states SET consumed_at = now()
WHERE id = sqlc.arg(id) AND consumed_at IS NULL;

-- name: GetExternalIdentity :one
SELECT id, user_id, issuer, subject, created_at
FROM external_identities
WHERE issuer = sqlc.arg(issuer) AND subject = sqlc.arg(subject);

-- name: CreateExternalIdentity :one
INSERT INTO external_identities (id, user_id, issuer, subject)
VALUES (sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(issuer), sqlc.arg(subject))
RETURNING id, user_id, issuer, subject, created_at;

-- name: MarkExternalUserVerified :exec
UPDATE users SET email_verified_at = COALESCE(email_verified_at, now()), status = 'active', updated_at = now()
WHERE id = sqlc.arg(id);

-- name: GetRoleByNameInSpace :one
SELECT id, space_id, name, description, managed, created_at
FROM roles WHERE space_id = sqlc.arg(space_id) AND name = sqlc.arg(name);
