-- name: CreateSSOConnection :one
INSERT INTO sso_connections (
    id, space_id, name, provider, issuer, client_id, client_secret_ciphertext,
    redirect_uri, groups_claim, role_mappings, status, saml_entity_id, saml_sso_url,
    saml_sso_binding, saml_idp_certificate
)
VALUES (
    sqlc.arg(id), sqlc.arg(space_id), sqlc.arg(name), sqlc.arg(provider),
    sqlc.arg(issuer), sqlc.arg(client_id), sqlc.narg(client_secret_ciphertext),
    sqlc.arg(redirect_uri), sqlc.arg(groups_claim), sqlc.arg(role_mappings), 'active',
    sqlc.narg(saml_entity_id), sqlc.narg(saml_sso_url), sqlc.narg(saml_sso_binding),
    sqlc.narg(saml_idp_certificate)
)
RETURNING id, space_id, name, provider, issuer, client_id, redirect_uri, groups_claim,
    role_mappings, status, created_at, updated_at, saml_entity_id, saml_sso_url,
    saml_sso_binding, saml_idp_certificate;

-- name: GetSSOConnection :one
SELECT id, space_id, name, provider, issuer, client_id, client_secret_ciphertext,
    redirect_uri, groups_claim, role_mappings, status, created_at, updated_at,
    saml_entity_id, saml_sso_url, saml_sso_binding, saml_idp_certificate
FROM sso_connections WHERE id = sqlc.arg(id);

-- name: ListSSOConnections :many
SELECT id, space_id, name, provider, issuer, client_id, redirect_uri, groups_claim,
    role_mappings, status, created_at, updated_at, saml_entity_id, saml_sso_url,
    saml_sso_binding, saml_idp_certificate
FROM sso_connections WHERE space_id = sqlc.arg(space_id)
ORDER BY created_at, id;

-- name: LockSSOConnection :one
SELECT id, space_id, name, provider, issuer, client_id, client_secret_ciphertext,
    redirect_uri, groups_claim, role_mappings, status, created_at, updated_at,
    saml_entity_id, saml_sso_url, saml_sso_binding, saml_idp_certificate
FROM sso_connections WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: DisableSSOConnection :exec
UPDATE sso_connections SET status = 'disabled', updated_at = now()
WHERE id = sqlc.arg(id) AND status <> 'disabled';

-- name: CreateSSOState :one
INSERT INTO sso_states (
    id, connection_id, state_hash, nonce_hash, pkce_verifier_ciphertext,
    redirect_uri, expires_at, request_id
)
VALUES (
    sqlc.arg(id), sqlc.arg(connection_id), sqlc.arg(state_hash), sqlc.arg(nonce_hash),
    sqlc.arg(pkce_verifier_ciphertext), sqlc.arg(redirect_uri), sqlc.arg(expires_at),
    sqlc.narg(request_id)
)
RETURNING id, connection_id, state_hash, nonce_hash, pkce_verifier_ciphertext,
    redirect_uri, expires_at, consumed_at, created_at, request_id;

-- name: LockSSOStateByHash :one
SELECT id, connection_id, state_hash, nonce_hash, pkce_verifier_ciphertext,
    redirect_uri, expires_at, consumed_at, created_at, request_id
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
