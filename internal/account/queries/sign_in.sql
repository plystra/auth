-- name: CreateSignInAttempt :one
INSERT INTO sign_in_attempts (
    id, user_id, email_normalized, ip, user_agent, expires_at
)
VALUES (
    sqlc.arg(id), sqlc.narg(user_id), sqlc.arg(email_normalized),
    sqlc.narg(ip), sqlc.narg(user_agent), sqlc.arg(expires_at)
)
RETURNING id, user_id, email_normalized, ip, user_agent, failed_attempts, expires_at, consumed_at, locked_at, created_at;

-- name: LockSignInAttempt :one
SELECT id, user_id, email_normalized, ip, user_agent, failed_attempts, expires_at, consumed_at, locked_at, created_at
FROM sign_in_attempts
WHERE id = sqlc.arg(id)
FOR UPDATE;

-- name: GetSignInAttemptRateIdentity :one
SELECT email_normalized
FROM sign_in_attempts
WHERE id = sqlc.arg(id)
  AND expires_at > now()
  AND consumed_at IS NULL
  AND locked_at IS NULL;

-- name: IncrementSignInAttemptFailure :one
UPDATE sign_in_attempts
SET failed_attempts = failed_attempts + 1,
    locked_at = CASE WHEN failed_attempts + 1 >= sqlc.arg(max_failures) THEN now() ELSE locked_at END
WHERE id = sqlc.arg(id)
RETURNING id, user_id, email_normalized, ip, user_agent, failed_attempts, expires_at, consumed_at, locked_at, created_at;

-- name: ConsumeSignInAttempt :exec
UPDATE sign_in_attempts
SET consumed_at = now()
WHERE id = sqlc.arg(id) AND consumed_at IS NULL AND locked_at IS NULL;
