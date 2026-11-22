-- name: ListPublicApplicationReviews :many
SELECT id, space_id, name, client_id, redirect_uris, manifest_permissions,
       pending_manifest_permissions, review_status, human_oidc_enabled, status, created_at
FROM applications
WHERE visibility = 'public'
ORDER BY created_at, id;

-- name: LockPublicApplicationReview :one
SELECT id, space_id, name, client_id, redirect_uris, manifest_permissions,
       pending_manifest_permissions, review_status, human_oidc_enabled, status, created_at
FROM applications
WHERE id = sqlc.arg(application_id) AND visibility = 'public'
FOR UPDATE;

-- name: ApprovePublicApplicationReview :execrows
UPDATE applications
SET manifest_permissions = sqlc.arg(manifest_permissions),
    allowed_scopes = sqlc.arg(manifest_permissions),
    pending_manifest_permissions = NULL,
    review_status = 'approved'
WHERE id = sqlc.arg(application_id) AND visibility = 'public'
  AND pending_manifest_permissions IS NOT NULL;

-- name: SuspendApplicationGlobally :exec
UPDATE applications SET status = 'suspended'
WHERE id = sqlc.arg(application_id);

-- name: ListApplicationSuspensionMembers :many
SELECT m.id, m.space_id, m.type
FROM members m
WHERE m.status <> 'removed' AND (
    (m.type = 'application' AND EXISTS (
        SELECT 1 FROM application_installations i
        WHERE i.application_id = sqlc.arg(application_id) AND i.member_id = m.id
    ))
    OR (m.type = 'agent' AND m.source = 'oauth' AND m.oauth_client_id = sqlc.arg(client_id))
)
ORDER BY m.id;

-- name: SuspendApplicationMember :exec
UPDATE members SET status = 'suspended', version = version + 1
WHERE id = sqlc.arg(member_id) AND type = 'application' AND status = 'active';

-- name: RejectPublicApplicationReview :execrows
UPDATE applications
SET pending_manifest_permissions = NULL,
    review_status = CASE WHEN review_status = 'approved' THEN 'approved' ELSE 'rejected' END
WHERE id = sqlc.arg(application_id) AND visibility = 'public'
  AND pending_manifest_permissions IS NOT NULL;
