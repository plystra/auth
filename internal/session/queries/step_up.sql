-- name: LockSessionForStepUp :one
SELECT id, user_id, member_id, token_hash, created_at, last_seen_at, expires_at,
       revoked_at, ip, user_agent, auth_time, assurance_level,
       step_up_operation, step_up_digest, step_up_expires_at
FROM sessions
WHERE id = sqlc.arg(id)
FOR UPDATE;

-- name: SetSessionStepUp :one
UPDATE sessions
SET step_up_operation = sqlc.arg(operation),
    step_up_digest = sqlc.arg(digest),
    step_up_expires_at = now() + interval '5 minutes',
    assurance_level = GREATEST(assurance_level, 2)
WHERE id = sqlc.arg(id)
  AND revoked_at IS NULL
  AND expires_at > now()
RETURNING id, user_id, member_id, token_hash, created_at, last_seen_at, expires_at,
          revoked_at, ip, user_agent, auth_time, assurance_level,
          step_up_operation, step_up_digest, step_up_expires_at;

-- name: ConsumeSessionStepUp :one
UPDATE sessions
SET step_up_operation = NULL,
    step_up_digest = NULL,
    step_up_expires_at = NULL
WHERE id = sqlc.arg(id)
  AND step_up_operation = sqlc.arg(operation)
  AND step_up_digest = sqlc.arg(digest)
  AND step_up_expires_at > now()
  AND revoked_at IS NULL
  AND expires_at > now()
RETURNING user_id;
