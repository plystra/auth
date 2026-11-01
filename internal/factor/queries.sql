-- name: CreateFactor :one
INSERT INTO factors (id, user_id, kind, name, secret_ciphertext, credential_id, public_key, counter) VALUES (sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(kind), sqlc.arg(name), sqlc.narg(secret_ciphertext), sqlc.narg(credential_id), sqlc.narg(public_key), COALESCE(sqlc.narg(counter), 0)) RETURNING id, user_id, kind, name, secret_ciphertext, credential_id, public_key, counter, created_at, last_used_at;

-- name: DeleteBackupCodes :exec
DELETE FROM factors WHERE user_id = sqlc.arg(user_id) AND kind = 'backup_code';

-- name: LockFactorForUser :one
SELECT * FROM factors
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id)
FOR UPDATE;

-- name: DeleteFactor :exec
DELETE FROM factors
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id);

-- name: InvalidatePasswordStepUpForUser :exec
UPDATE sessions
SET step_up_operation = NULL, step_up_digest = NULL, step_up_method = NULL, step_up_expires_at = NULL
WHERE user_id = sqlc.arg(user_id) AND step_up_method = 'password';

-- name: CreateBackupCode :one
INSERT INTO factors (id, user_id, kind, name, secret_hash)
VALUES (sqlc.arg(id), sqlc.arg(user_id), 'backup_code', sqlc.arg(name), sqlc.arg(secret_hash))
RETURNING id, user_id, kind, name, secret_ciphertext, secret_hash, credential_id, public_key, counter, created_at, last_used_at;

-- name: GetUnusedBackupCodeByHash :one
SELECT id, user_id, kind, name, secret_ciphertext, secret_hash, credential_id, public_key, counter, created_at, last_used_at
FROM factors
WHERE user_id = sqlc.arg(user_id)
  AND kind = 'backup_code'
  AND secret_hash = sqlc.arg(secret_hash)
  AND last_used_at IS NULL
FOR UPDATE;

-- name: ConsumeBackupCode :exec
UPDATE factors SET last_used_at = now()
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id) AND kind = 'backup_code' AND last_used_at IS NULL;

-- name: ListFactors :many
SELECT id, user_id, kind, name, secret_ciphertext, credential_id, public_key, counter, created_at, last_used_at FROM factors WHERE user_id = sqlc.arg(user_id) ORDER BY created_at;

-- name: TouchFactor :exec
UPDATE factors SET last_used_at = now(), counter = COALESCE(sqlc.narg(counter), counter) WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id);

-- name: LockTOTPFactors :many
SELECT * FROM factors WHERE user_id = sqlc.arg(user_id) AND kind = 'totp' ORDER BY id FOR UPDATE;

-- name: ConsumeTOTPStep :one
UPDATE factors SET counter = sqlc.arg(step)::bigint, last_used_at = now()
WHERE id = sqlc.arg(id) AND counter < sqlc.arg(step)::bigint RETURNING id;

-- name: CreatePasskeyChallenge :exec
INSERT INTO passkey_challenges (id, user_id, session_id, name, session_data, expires_at)
VALUES (sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(session_id), sqlc.arg(name), sqlc.arg(session_data), sqlc.arg(expires_at));

-- name: LockPasskeyChallenge :one
SELECT id, user_id, session_id, name, session_data, expires_at, consumed_at, created_at
FROM passkey_challenges WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: ConsumePasskeyChallenge :exec
UPDATE passkey_challenges SET consumed_at = now()
WHERE id = sqlc.arg(id) AND consumed_at IS NULL AND expires_at > now();

-- name: ListPasskeysForUser :many
SELECT id, user_id, kind, name, secret_ciphertext, credential_id, public_key, counter, created_at, last_used_at
FROM factors WHERE user_id = sqlc.arg(user_id) AND kind = 'webauthn' ORDER BY id;
