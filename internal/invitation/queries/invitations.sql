-- name: CreateInvitationToken :one
INSERT INTO invitation_tokens (
    id, space_id, email_normalized, member_id, token_hash, expires_at
)
VALUES (
    sqlc.arg(id), sqlc.arg(space_id), sqlc.narg(email_normalized),
    sqlc.narg(member_id), sqlc.arg(token_hash), sqlc.arg(expires_at)
)
RETURNING id, space_id, email_normalized, member_id, token_hash, expires_at, consumed_at, created_at;

-- name: ConsumeInvitationToken :one
UPDATE invitation_tokens
SET consumed_at = now()
WHERE token_hash = sqlc.arg(token_hash)
  AND consumed_at IS NULL
  AND expires_at > now()
RETURNING id, space_id, email_normalized, member_id, token_hash, expires_at, consumed_at, created_at;

-- name: GetInvitationForRegistration :one
SELECT id, space_id, email_normalized, member_id, token_hash, expires_at, consumed_at, created_at
FROM invitation_tokens
WHERE token_hash = sqlc.arg(token_hash) AND consumed_at IS NULL AND expires_at > now()
FOR UPDATE;

-- name: GetInvitationByToken :one
SELECT id, space_id, email_normalized, member_id, token_hash, expires_at, consumed_at, created_at
FROM invitation_tokens
WHERE token_hash = sqlc.arg(token_hash) AND consumed_at IS NULL AND expires_at > now();

-- name: CreatePendingInvitationRegistration :exec
INSERT INTO pending_invitation_registrations (user_id, invitation_id)
VALUES (sqlc.arg(user_id), sqlc.arg(invitation_id));

-- name: GetPendingInvitationForUser :one
SELECT invitation_id FROM pending_invitation_registrations
WHERE user_id = sqlc.arg(user_id) FOR UPDATE;

-- name: ConsumeInvitationByID :one
UPDATE invitation_tokens SET consumed_at = now()
WHERE id = sqlc.arg(id) AND consumed_at IS NULL AND expires_at > now()
RETURNING id, space_id, email_normalized, member_id, token_hash, expires_at, consumed_at, created_at;

-- name: DeletePendingInvitationRegistration :exec
DELETE FROM pending_invitation_registrations WHERE user_id = sqlc.arg(user_id);
