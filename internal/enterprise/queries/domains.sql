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
FROM sso_domains WHERE id = sqlc.arg(id) AND space_id = sqlc.arg(space_id) FOR UPDATE;

-- name: LockForcedSSODomainForLogin :exec
SELECT pg_advisory_xact_lock_shared(hashtextextended(sqlc.arg(domain)::text, 723615832002));

-- name: LockForcedSSODomainForChange :exec
SELECT pg_advisory_xact_lock(hashtextextended(sqlc.arg(domain)::text, 723615832002));

-- name: VerifySSODomain :exec
UPDATE sso_domains SET status = 'verified', verified_at = now(),
    updated_at = greatest(clock_timestamp(), updated_at + interval '1 microsecond')
WHERE id = sqlc.arg(id) AND status = 'pending';

-- name: DisableSSODomain :exec
UPDATE sso_domains SET status = 'disabled',
    updated_at = greatest(clock_timestamp(), updated_at + interval '1 microsecond')
WHERE id = sqlc.arg(id) AND status <> 'disabled';

-- name: UpdateSSODomainEnforcement :one
UPDATE sso_domains SET force_sso = sqlc.arg(force_sso),
    updated_at = greatest(clock_timestamp(), updated_at + interval '1 microsecond')
WHERE id = sqlc.arg(id) AND space_id = sqlc.arg(space_id) AND status = 'verified'
RETURNING id, space_id, domain, connection_id, force_sso, covers_subtree, status, verified_at, created_at, updated_at;

-- name: GetSSOForEmailDomain :one
SELECT d.id, d.space_id, d.domain, d.connection_id, d.force_sso, d.covers_subtree, d.status,
    c.id AS sso_connection_id, c.status AS sso_connection_status, c.covers_subtree AS sso_connection_covers_subtree
FROM sso_domains d
LEFT JOIN sso_connections c ON c.id = d.connection_id
WHERE d.domain = sqlc.arg(domain) AND d.status = 'verified'
  AND (d.force_sso OR (sqlc.arg(include_optional)::boolean AND d.connection_id IS NOT NULL));

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
LEFT JOIN sso_connections c ON c.id = d.connection_id
JOIN ancestors ON ancestors.id = d.space_id
WHERE d.domain = sqlc.arg(domain)
  AND d.status = 'verified'
  AND d.force_sso = true
  AND (ancestors.depth = 0 OR (d.covers_subtree AND (c.covers_subtree OR c.id IS NULL)))
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
