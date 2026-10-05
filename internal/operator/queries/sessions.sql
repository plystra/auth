-- name: CreateOperatorSession :one
INSERT INTO operator_sessions (id, user_id, token_hash, expires_at, idle_expires_at, access_expires_at, assurance_level, ip, user_agent)
VALUES (sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(token_hash), sqlc.arg(expires_at), sqlc.arg(idle_expires_at), sqlc.arg(access_expires_at), 2, sqlc.narg(ip), sqlc.narg(user_agent))
RETURNING *;

-- name: LockOperatorSession :one
SELECT s.* FROM operator_sessions s
WHERE s.token_hash = sqlc.arg(token_hash) AND s.revoked_at IS NULL
  AND s.expires_at > now() AND s.idle_expires_at > now() AND s.access_expires_at > now()
FOR UPDATE;

-- name: TouchOperatorSession :exec
UPDATE operator_sessions
SET last_seen_at = now(), idle_expires_at = LEAST(expires_at, now() + interval '30 minutes')
WHERE id = sqlc.arg(id);

-- name: StepUpOperatorSession :one
UPDATE operator_sessions
SET step_up_operation = sqlc.arg(operation), step_up_digest = sqlc.arg(digest), step_up_expires_at = now() + interval '5 minutes'
WHERE id = sqlc.arg(id) AND revoked_at IS NULL AND expires_at > now() AND idle_expires_at > now() AND access_expires_at > now()
RETURNING *;

-- name: ConsumeOperatorStepUp :one
UPDATE operator_sessions SET step_up_operation = NULL, step_up_digest = NULL, step_up_expires_at = NULL
WHERE id = sqlc.arg(id) AND step_up_operation = sqlc.arg(operation) AND step_up_digest = sqlc.arg(digest)
  AND step_up_expires_at > now() AND revoked_at IS NULL AND access_expires_at > now()
RETURNING id;

-- name: RevokeOperatorSession :exec
UPDATE operator_sessions SET revoked_at = COALESCE(revoked_at, now()) WHERE id = sqlc.arg(id);
