-- name: CreateSignInAttempt :one
INSERT INTO sign_in_attempts (
    id, user_id, email_normalized, ip, user_agent, expires_at
)
VALUES (
    sqlc.arg(id), sqlc.narg(user_id), sqlc.arg(email_normalized),
    sqlc.narg(ip), sqlc.narg(user_agent), sqlc.arg(expires_at)
)
RETURNING *;

-- name: CreatePasskeySignInAttempt :one
INSERT INTO sign_in_attempts (
    id, user_id, email_normalized, ip, user_agent, expires_at, method, passkey_session
)
VALUES (
    sqlc.arg(id), sqlc.narg(user_id), sqlc.arg(email_normalized),
    sqlc.narg(ip), sqlc.narg(user_agent), sqlc.arg(expires_at), 'passkey', sqlc.arg(passkey_session)
)
RETURNING *;

-- name: LockSignInAttempt :one
SELECT *
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
RETURNING *;

-- name: MarkSignInPasswordVerified :exec
UPDATE sign_in_attempts
SET password_verified_at = now()
WHERE id = sqlc.arg(id) AND password_verified_at IS NULL
  AND consumed_at IS NULL AND locked_at IS NULL AND expires_at > now();

-- name: ConsumeSignInAttempt :exec
UPDATE sign_in_attempts
SET consumed_at = now()
WHERE id = sqlc.arg(id) AND consumed_at IS NULL AND locked_at IS NULL;
