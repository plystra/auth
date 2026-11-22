-- name: CreateSSODomain :one
INSERT INTO sso_domains (
    id, space_id, domain, verification_token_hash, connection_id, force_sso, status
)
VALUES (
    sqlc.arg(id), sqlc.arg(space_id), sqlc.arg(domain), sqlc.arg(verification_token_hash),
    sqlc.narg(connection_id), sqlc.arg(force_sso), 'pending'
)
RETURNING id, space_id, domain, verification_token_hash, connection_id, force_sso, status,
    verified_at, created_at, updated_at;

-- name: GetSSODomain :one
SELECT id, space_id, domain, verification_token_hash, connection_id, force_sso, status,
    verified_at, created_at, updated_at
FROM sso_domains WHERE id = sqlc.arg(id);

-- name: ListSSODomains :many
SELECT id, space_id, domain, connection_id, force_sso, status, verified_at, created_at, updated_at
FROM sso_domains WHERE space_id = sqlc.arg(space_id)
ORDER BY created_at, id;

-- name: LockSSODomain :one
SELECT id, space_id, domain, verification_token_hash, connection_id, force_sso, status,
    verified_at, created_at, updated_at
FROM sso_domains WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: VerifySSODomain :exec
UPDATE sso_domains SET status = 'verified', verified_at = now(), updated_at = now()
WHERE id = sqlc.arg(id) AND status = 'pending';

-- name: DisableSSODomain :exec
UPDATE sso_domains SET status = 'disabled', updated_at = now()
WHERE id = sqlc.arg(id) AND status <> 'disabled';

-- name: GetForcedSSOForEmailDomain :one
SELECT d.id, d.space_id, d.domain, d.connection_id, d.force_sso, d.status,
    c.id AS sso_connection_id, c.status AS sso_connection_status
FROM sso_domains d
LEFT JOIN sso_connections c ON c.id = d.connection_id
WHERE d.domain = sqlc.arg(domain) AND d.status = 'verified' AND d.force_sso = true;
