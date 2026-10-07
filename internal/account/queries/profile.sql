-- name: GetUserProfileByID :one
SELECT id, email, status, email_verified_at, disabled_at, display_name, avatar_url, public_metadata, created_at
FROM users
WHERE id = sqlc.arg(id)
LIMIT 1;

-- name: UpdateUserProfile :one
UPDATE users
SET display_name = COALESCE(sqlc.narg(display_name), display_name),
    avatar_url = COALESCE(sqlc.narg(avatar_url), avatar_url),
    public_metadata = COALESCE(sqlc.narg(public_metadata)::jsonb, public_metadata),
    updated_at = now()
WHERE id = sqlc.arg(id)
RETURNING id, email, status, email_verified_at, disabled_at, display_name, avatar_url, public_metadata, created_at;
