-- name: GetAPIKeyByPrefix :one
SELECT k.id, k.application_id, k.name, k.prefix, k.secret_hash, k.hash_scheme, k.scopes, k.restrict_to, k.allowed_ip_cidrs,
       k.expires_at, k.last_used_at, k.revoked_at, k.created_at, k.allow_subject_assertion,
       a.space_id, a.name AS application_name, a.client_id, a.status AS application_status,
       a.visibility AS application_visibility, a.review_status AS application_review_status
FROM api_keys k JOIN applications a ON a.id = k.application_id
WHERE k.prefix = sqlc.arg(prefix) LIMIT 1;

-- name: TouchAPIKey :exec
UPDATE api_keys SET last_used_at = now() WHERE id = sqlc.arg(id);

-- name: ValidGraceAPIKeySecret :one
SELECT EXISTS (
    SELECT 1 FROM api_key_grace_secrets
    WHERE key_id = sqlc.arg(key_id) AND secret_hash = sqlc.arg(secret_hash)
      AND valid_until > now()
);

-- name: LockLegacyAPIKeyHashes :many
SELECT id, secret_hash FROM api_keys
WHERE hash_scheme = 'sha256_legacy'
ORDER BY id LIMIT 500
FOR UPDATE;

-- name: UpdateAPIKeyHash :execrows
UPDATE api_keys
SET secret_hash = sqlc.arg(secret_hash), hash_scheme = 'hmac_sha256',
    revoked_at = CASE WHEN expires_at IS NULL THEN COALESCE(revoked_at, now()) ELSE revoked_at END
WHERE id = sqlc.arg(id) AND secret_hash = sqlc.arg(previous_hash)
  AND hash_scheme = sqlc.arg(previous_scheme);

-- name: CreateApplication :one
INSERT INTO applications (id, space_id, name, redirect_uris, allowed_scopes, client_id, client_secret_hash,
                          manifest_permissions, visibility, review_status, pending_manifest_permissions)
VALUES (sqlc.arg(id), sqlc.arg(space_id), sqlc.arg(name), COALESCE(sqlc.narg(redirect_uris), '[]'::jsonb),
        COALESCE(sqlc.narg(allowed_scopes), '[]'::jsonb), sqlc.arg(client_id), sqlc.narg(client_secret_hash),
        sqlc.arg(manifest_permissions), sqlc.arg(visibility), sqlc.arg(review_status), sqlc.narg(pending_manifest_permissions))
RETURNING id, space_id, name, redirect_uris, allowed_scopes, client_id, client_secret_hash,
          manifest_permissions, visibility, review_status, pending_manifest_permissions, status, created_at;

-- name: ListPublishedApplications :many
SELECT id, space_id, name, client_id, redirect_uris, manifest_permissions, visibility,
       review_status, pending_manifest_permissions, status, created_at
FROM applications
WHERE space_id = sqlc.arg(space_id)
ORDER BY created_at, id;

-- name: LockApplicationForUpdate :one
SELECT id, space_id, name, client_id, redirect_uris, manifest_permissions, visibility,
       review_status, pending_manifest_permissions, status, created_at
FROM applications WHERE id = sqlc.arg(application_id)
FOR UPDATE;

-- name: UpdateApplication :one
UPDATE applications
SET name = sqlc.arg(name), redirect_uris = sqlc.arg(redirect_uris),
    manifest_permissions = sqlc.arg(manifest_permissions),
    allowed_scopes = sqlc.arg(manifest_permissions),
    pending_manifest_permissions = sqlc.narg(pending_manifest_permissions),
    review_status = sqlc.arg(review_status)
WHERE id = sqlc.arg(application_id)
RETURNING id, space_id, name, client_id, redirect_uris, manifest_permissions,
          pending_manifest_permissions, visibility, review_status, status, created_at;

-- name: TrimInstallationApprovalsToManifest :exec
UPDATE application_installations i
SET approved_permissions = COALESCE((
    SELECT jsonb_agg(entry.key ORDER BY entry.key)
    FROM jsonb_array_elements_text(i.approved_permissions) AS entry(key)
    WHERE sqlc.arg(manifest_permissions)::jsonb ? entry.key
), '[]'::jsonb)
WHERE i.application_id = sqlc.arg(application_id) AND i.status <> 'uninstalled'
  AND EXISTS (
    SELECT 1 FROM jsonb_array_elements_text(i.approved_permissions) AS entry(key)
    WHERE NOT (sqlc.arg(manifest_permissions)::jsonb ? entry.key)
  );

-- name: TrimInstallationRolePermissionsToManifest :exec
DELETE FROM role_permissions rp
USING application_installations i, permissions p
WHERE i.application_id = sqlc.arg(application_id) AND i.status <> 'uninstalled'
  AND rp.role_id = i.role_id AND p.id = rp.permission_id
  AND NOT (sqlc.arg(manifest_permissions)::jsonb ? p.key);

-- name: ListManifestInstallationMembers :many
SELECT id, member_id, space_id, anchor_group_id FROM application_installations
WHERE application_id = sqlc.arg(application_id) AND status <> 'uninstalled'
ORDER BY space_id, id;

-- name: TrimAPIKeyGrantsToManifest :exec
UPDATE api_keys k
SET scopes = COALESCE((
    SELECT jsonb_agg(entry.key ORDER BY entry.key)
    FROM jsonb_array_elements_text(k.scopes) AS entry(key)
    WHERE sqlc.arg(manifest_permissions)::jsonb ? entry.key
), '[]'::jsonb)
WHERE k.application_id = sqlc.arg(application_id)
  AND EXISTS (
    SELECT 1 FROM jsonb_array_elements_text(k.scopes) AS entry(key)
    WHERE NOT (sqlc.arg(manifest_permissions)::jsonb ? entry.key)
  );

-- name: GetInstallationApplicationIdentity :one
SELECT application_id, space_id FROM application_installations
WHERE id = sqlc.arg(installation_id);

-- name: SetInstallationApprovedPermissions :execrows
UPDATE application_installations
SET approved_permissions = sqlc.arg(approved_permissions)
WHERE id = sqlc.arg(installation_id) AND status <> 'uninstalled';

-- name: GetApplicationForInstall :one
WITH RECURSIVE ancestors AS (
    SELECT spaces.id, spaces.parent_id FROM spaces WHERE spaces.id = sqlc.arg(target_space_id) AND spaces.status = 'active'
    UNION ALL
    SELECT parent.id, parent.parent_id FROM spaces parent
    JOIN ancestors child ON child.parent_id = parent.id
    WHERE parent.status = 'active'
)
SELECT a.id, a.space_id, a.name, a.manifest_permissions, a.status
FROM applications a
WHERE a.id = sqlc.arg(application_id) AND a.status = 'active'
  AND ((a.visibility = 'private' AND a.space_id IN (SELECT id FROM ancestors))
       OR (a.visibility = 'public' AND a.review_status = 'approved'
           AND EXISTS (SELECT 1 FROM ancestors)))
LIMIT 1
FOR UPDATE OF a;

-- name: HasOverlappingApplicationInstallation :one
WITH RECURSIVE ancestors AS (
    SELECT id, parent_id FROM spaces WHERE id = sqlc.arg(target_space_id)
    UNION ALL
    SELECT parent.id, parent.parent_id FROM spaces parent
    JOIN ancestors child ON child.parent_id = parent.id
), descendants AS (
    SELECT id FROM spaces WHERE id = sqlc.arg(target_space_id)
    UNION ALL
    SELECT child.id FROM spaces child
    JOIN descendants parent ON child.parent_id = parent.id
)
SELECT EXISTS (
    SELECT 1 FROM application_installations i
    WHERE i.application_id = sqlc.arg(application_id) AND i.status <> 'uninstalled'
      AND (
          i.space_id = sqlc.arg(target_space_id)
          OR (i.scope = 'space_tree' AND i.space_id IN (SELECT id FROM ancestors))
          OR (sqlc.arg(new_scope)::text = 'space_tree' AND i.space_id IN (SELECT id FROM descendants))
      )
);

-- name: CreateApplicationInstallation :one
INSERT INTO application_installations (
    id, application_id, space_id, member_id, role_id, scope, anchor_group_id, approved_permissions, installed_by
) VALUES (
    sqlc.arg(id), sqlc.arg(application_id), sqlc.arg(space_id), sqlc.arg(member_id),
    sqlc.arg(role_id), sqlc.arg(scope), sqlc.narg(anchor_group_id), sqlc.arg(approved_permissions), sqlc.arg(installed_by)
)
RETURNING id, application_id, space_id, member_id, role_id, scope, anchor_group_id,
          approved_permissions, status, installed_by, created_at;

-- name: ListApplicationInstallationsInSpace :many
SELECT i.id, i.application_id, i.space_id, i.member_id, i.role_id, i.scope,
       i.anchor_group_id, i.approved_permissions, i.status, i.installed_by, i.created_at,
       a.name AS application_name
FROM application_installations i
JOIN applications a ON a.id = i.application_id
WHERE i.space_id = sqlc.arg(space_id) AND i.status <> 'uninstalled'
ORDER BY i.created_at, i.id;

-- name: GetInstallationTarget :one
SELECT space_id, anchor_group_id FROM application_installations WHERE id = sqlc.arg(installation_id);

-- name: ListKeyInstallations :many
WITH RECURSIVE allowed_spaces AS (
    SELECT s.id, COALESCE((r.value->>'include_descendants')::boolean, false) AS include_descendants
    FROM jsonb_array_elements(sqlc.arg(restrict_to)::jsonb) AS r(value)
    JOIN spaces s ON s.id = r.value->>'space_id' AND s.status = 'active'
    UNION
    SELECT child.id, parent.include_descendants
    FROM spaces child JOIN allowed_spaces parent ON child.parent_id = parent.id
    WHERE child.status = 'active' AND parent.include_descendants
)
SELECT i.id, i.application_id, i.space_id, i.member_id, i.scope, i.anchor_group_id,
       i.approved_permissions, i.status, i.created_at, a.name AS application_name
FROM application_installations i
JOIN applications a ON a.id = i.application_id
JOIN members m ON m.id = i.member_id
JOIN spaces s ON s.id = i.space_id
WHERE i.application_id = sqlc.arg(application_id)
  AND i.status = 'active' AND a.status = 'active' AND m.status = 'active' AND s.status = 'active'
  AND (a.visibility <> 'public' OR a.review_status = 'approved')
  AND (sqlc.arg(restrict_to)::jsonb = '[]'::jsonb OR i.space_id IN (SELECT id FROM allowed_spaces))
  AND i.id > sqlc.arg(after_id)::text
ORDER BY i.id
LIMIT sqlc.arg(limit_count);

-- name: LockInstallationForLifecycle :one
SELECT i.id, i.application_id, i.space_id, i.member_id, i.role_id, i.scope,
       i.anchor_group_id, i.approved_permissions, i.status, i.created_at,
       a.name AS application_name, a.status AS application_status,
       m.status AS member_status
FROM application_installations i
JOIN applications a ON a.id = i.application_id
JOIN members m ON m.id = i.member_id
WHERE i.id = sqlc.arg(installation_id) AND i.space_id = sqlc.arg(space_id)
FOR UPDATE OF i, m;

-- name: SetInstallationLifecycleStatus :execrows
UPDATE application_installations SET status = sqlc.arg(new_status)
WHERE id = sqlc.arg(installation_id) AND status = sqlc.arg(previous_status);

-- name: SetInstallationMemberStatus :execrows
UPDATE members
SET status = sqlc.arg(new_status),
    deleted_at = CASE WHEN sqlc.arg(new_status) = 'removed' THEN now() ELSE deleted_at END,
    version = version + 1
WHERE id = sqlc.arg(member_id) AND type = 'application'
  AND status <> 'removed' AND status <> sqlc.arg(new_status);

-- name: GetActiveApplicationInstallationForSpace :one
WITH RECURSIVE ancestors AS (
    SELECT spaces.id, spaces.parent_id, 0 AS depth
    FROM spaces WHERE spaces.id = sqlc.arg(target_space_id) AND spaces.status = 'active'
    UNION ALL
    SELECT parent.id, parent.parent_id, child.depth + 1
    FROM spaces parent JOIN ancestors child ON child.parent_id = parent.id
    WHERE parent.status = 'active'
)
SELECT i.id, i.member_id, i.space_id, i.scope, i.approved_permissions
FROM application_installations i
JOIN ancestors ON ancestors.id = i.space_id
JOIN applications a ON a.id = i.application_id
JOIN members m ON m.id = i.member_id
WHERE i.application_id = sqlc.arg(application_id)
  AND i.status = 'active' AND a.status = 'active' AND m.status = 'active'
  AND (i.space_id = sqlc.arg(target_space_id) OR i.scope = 'space_tree')
ORDER BY ancestors.depth
LIMIT 1;

-- name: LockActiveApplicationInstallationForSpace :one
WITH RECURSIVE ancestors AS (
    SELECT spaces.id, spaces.parent_id, 0 AS depth
    FROM spaces WHERE spaces.id = sqlc.arg(target_space_id) AND spaces.status = 'active'
    UNION ALL
    SELECT parent.id, parent.parent_id, child.depth + 1
    FROM spaces parent JOIN ancestors child ON child.parent_id = parent.id
    WHERE parent.status = 'active'
)
SELECT i.id, i.member_id, i.space_id, i.scope, i.approved_permissions
FROM application_installations i
JOIN ancestors ON ancestors.id = i.space_id
JOIN applications a ON a.id = i.application_id
JOIN members m ON m.id = i.member_id
WHERE i.application_id = sqlc.arg(application_id)
  AND i.status = 'active' AND a.status = 'active' AND m.status = 'active'
  AND (i.space_id = sqlc.arg(target_space_id) OR i.scope = 'space_tree')
ORDER BY ancestors.depth
LIMIT 1
FOR SHARE OF i, m, a;

-- name: ListActiveSpaceAncestorsForKey :many
WITH RECURSIVE ancestors AS (
    SELECT spaces.id, spaces.parent_id
    FROM spaces WHERE spaces.id = sqlc.arg(target_space_id) AND spaces.status = 'active'
    UNION ALL
    SELECT parent.id, parent.parent_id
    FROM spaces parent JOIN ancestors child ON child.parent_id = parent.id
    WHERE parent.status = 'active'
)
SELECT id FROM ancestors;

-- name: GetApplicationByClientID :one
SELECT id, space_id, name, redirect_uris, allowed_scopes, client_id, client_secret_hash,
       visibility, review_status, status, created_at
FROM applications
WHERE client_id = sqlc.arg(client_id)
LIMIT 1;

-- name: GetOAuthClientByID :one
SELECT id, space_id, name, redirect_uris, allowed_scopes, client_id, client_secret_hash,
       visibility, review_status, status, created_at
FROM applications
WHERE id = sqlc.arg(id)
FOR UPDATE;

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

-- name: CreateOAuthAuthorizationRequest :exec
INSERT INTO oauth_authorization_requests (
    id, request_hash, application_id, redirect_uri, code_challenge,
    scope, state, nonce, resource, expires_at
) VALUES (
    sqlc.arg(id), sqlc.arg(request_hash), sqlc.arg(application_id),
    sqlc.arg(redirect_uri), sqlc.arg(code_challenge), sqlc.arg(scope),
    sqlc.arg(state), sqlc.arg(nonce), sqlc.arg(resource), sqlc.arg(expires_at)
);

-- name: LockOAuthAuthorizationRequest :one
SELECT id, application_id, redirect_uri, code_challenge, scope, state, nonce, resource, expires_at
FROM oauth_authorization_requests
WHERE request_hash = sqlc.arg(request_hash)
  AND status = 'pending' AND expires_at > now()
FOR UPDATE;

-- name: FinishOAuthAuthorizationRequest :execrows
UPDATE oauth_authorization_requests
SET status = sqlc.arg(status), consumed_at = now()
WHERE id = sqlc.arg(id) AND status = 'pending' AND expires_at > now();

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
INSERT INTO api_keys (id, application_id, name, prefix, secret_hash, scopes, restrict_to, allowed_ip_cidrs, expires_at, allow_subject_assertion)
VALUES (sqlc.arg(id), sqlc.arg(application_id), sqlc.arg(name), sqlc.arg(prefix), sqlc.arg(secret_hash), COALESCE(sqlc.narg(scopes), '[]'::jsonb), COALESCE(sqlc.narg(restrict_to), '[]'::jsonb), COALESCE(sqlc.narg(allowed_ip_cidrs), '[]'::jsonb), sqlc.narg(expires_at), sqlc.arg(allow_subject_assertion))
RETURNING id, application_id, name, prefix, secret_hash, scopes, restrict_to, allowed_ip_cidrs, expires_at, last_used_at, revoked_at, created_at, allow_subject_assertion;

-- name: GetApplicationForKeyManagement :one
SELECT id, space_id, manifest_permissions, status, visibility, review_status
FROM applications WHERE id = sqlc.arg(application_id);

-- name: ListManagedAPIKeys :many
SELECT id, application_id, name, prefix, scopes, restrict_to, allowed_ip_cidrs, expires_at,
       last_used_at, revoked_at, created_at, allow_subject_assertion
FROM api_keys WHERE application_id = sqlc.arg(application_id)
ORDER BY created_at, id;

-- name: RevokeManagedAPIKey :one
UPDATE api_keys SET revoked_at = COALESCE(revoked_at, now())
WHERE id = sqlc.arg(key_id) AND application_id = sqlc.arg(application_id)
RETURNING id, application_id, name, prefix, scopes, restrict_to, allowed_ip_cidrs, expires_at,
          last_used_at, revoked_at, created_at, allow_subject_assertion;

-- name: LockManagedAPIKey :one
SELECT id, application_id, name, prefix, secret_hash, hash_scheme, scopes, restrict_to,
       allowed_ip_cidrs, expires_at, last_used_at, revoked_at, created_at, allow_subject_assertion
FROM api_keys
WHERE id = sqlc.arg(key_id) AND application_id = sqlc.arg(application_id)
FOR UPDATE;

-- name: UpdateManagedAPIKeyGrants :execrows
UPDATE api_keys SET scopes = sqlc.arg(scopes)
WHERE id = sqlc.arg(key_id) AND application_id = sqlc.arg(application_id)
  AND revoked_at IS NULL AND expires_at > now();

-- name: PreserveAPIKeySecretForGrace :exec
INSERT INTO api_key_grace_secrets (key_id, secret_hash, valid_until)
VALUES (sqlc.arg(key_id), sqlc.arg(secret_hash), now() + interval '24 hours');

-- name: ReplaceManagedAPIKeySecret :one
UPDATE api_keys SET secret_hash = sqlc.arg(secret_hash), hash_scheme = 'hmac_sha256'
WHERE id = sqlc.arg(key_id) AND application_id = sqlc.arg(application_id)
RETURNING id, application_id, name, prefix, scopes, restrict_to, allowed_ip_cidrs, expires_at,
          last_used_at, revoked_at, created_at, allow_subject_assertion;

-- name: GetActiveInstallationForKeyRestriction :one
SELECT scope FROM application_installations
WHERE application_id = sqlc.arg(application_id) AND space_id = sqlc.arg(space_id)
  AND status = 'active';
