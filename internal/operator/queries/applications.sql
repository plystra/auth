-- name: ListPublicApplicationReviews :many
SELECT id, space_id, name, client_id, redirect_uris, manifest_permissions,
       pending_manifest_permissions, review_status, status, created_at
FROM applications
WHERE visibility = 'public'
ORDER BY created_at, id;

-- name: LockPublicApplicationReview :one
SELECT id, space_id, name, client_id, redirect_uris, manifest_permissions,
       pending_manifest_permissions, review_status, status, created_at
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
  AND review_status = 'pending';

-- name: RejectPublicApplicationReview :execrows
UPDATE applications
SET pending_manifest_permissions = NULL, review_status = 'rejected'
WHERE id = sqlc.arg(application_id) AND visibility = 'public'
  AND review_status = 'pending';
