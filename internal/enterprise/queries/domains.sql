-- name: CreateSSODomain :one
INSERT INTO sso_domains (
    id, space_id, domain, verification_token_hash, connection_id, force_sso, covers_subtree, status
)
VALUES (
    sqlc.arg(id), sqlc.arg(space_id), sqlc.arg(domain), sqlc.arg(verification_token_hash),
    sqlc.narg(connection_id), sqlc.arg(force_sso), sqlc.arg(covers_subtree), 'pending'
)
RETURNING id, space_id, domain, verification_token_hash, connection_id, force_sso, covers_subtree, status,
    verified_at, created_at, updated_at;

-- name: GetSSODomain :one
SELECT id, space_id, domain, verification_token_hash, connection_id, force_sso, covers_subtree, status,
    verified_at, created_at, updated_at
FROM sso_domains WHERE id = sqlc.arg(id);

-- name: ListSSODomains :many
SELECT id, space_id, domain, connection_id, force_sso, covers_subtree, status, verified_at, created_at, updated_at
FROM sso_domains WHERE space_id = sqlc.arg(space_id)
ORDER BY created_at, id;

-- name: LockSSODomain :one
SELECT id, space_id, domain, verification_token_hash, connection_id, force_sso, covers_subtree, status,
    verified_at, created_at, updated_at
FROM sso_domains WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: VerifySSODomain :exec
UPDATE sso_domains SET status = 'verified', verified_at = now(), updated_at = now()
WHERE id = sqlc.arg(id) AND status = 'pending';

-- name: DisableSSODomain :exec
UPDATE sso_domains SET status = 'disabled', updated_at = now()
WHERE id = sqlc.arg(id) AND status <> 'disabled';

-- name: GetForcedSSOForEmailDomain :one
SELECT d.id, d.space_id, d.domain, d.connection_id, d.force_sso, d.covers_subtree, d.status,
    c.id AS sso_connection_id, c.status AS sso_connection_status, c.covers_subtree AS sso_connection_covers_subtree
FROM sso_domains d
LEFT JOIN sso_connections c ON c.id = d.connection_id
WHERE d.domain = sqlc.arg(domain) AND d.status = 'verified' AND d.force_sso = true;

-- name: GetForcedSSOForEmailDomainInSpace :one
WITH RECURSIVE ancestors AS (
    SELECT spaces.id, spaces.parent_id, 0 AS depth
    FROM spaces
    WHERE spaces.id = sqlc.arg(space_id)
    UNION ALL
    SELECT parent.id, parent.parent_id, ancestors.depth + 1
    FROM spaces parent
    JOIN ancestors ON parent.id = ancestors.parent_id
)
SELECT d.id, d.space_id, d.domain, d.connection_id, d.force_sso, d.covers_subtree, d.status,
    c.id AS sso_connection_id, c.status AS sso_connection_status, c.covers_subtree AS sso_connection_covers_subtree
FROM sso_domains d
JOIN sso_connections c ON c.id = d.connection_id
JOIN ancestors ON ancestors.id = d.space_id
WHERE d.domain = sqlc.arg(domain)
  AND d.status = 'verified'
  AND d.force_sso = true
  AND (ancestors.depth = 0 OR (d.covers_subtree AND c.covers_subtree))
ORDER BY ancestors.depth ASC, d.id ASC
LIMIT 1;

-- name: AreSpaceAncestorsActive :one
WITH RECURSIVE ancestors AS (
    SELECT spaces.id, spaces.parent_id, spaces.status
    FROM spaces
    WHERE spaces.id = sqlc.arg(space_id)
    UNION ALL
    SELECT parent.id, parent.parent_id, parent.status
    FROM spaces parent
    JOIN ancestors ON parent.id = ancestors.parent_id
)
SELECT COALESCE(bool_and(status = 'active'), false)::boolean AS active
FROM ancestors;
