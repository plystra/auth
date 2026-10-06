-- name: CreateSession :one
INSERT INTO sessions (id, user_id, member_id, token_hash, expires_at, ip, user_agent, auth_time, assurance_level)
VALUES (sqlc.arg(id), sqlc.arg(user_id), sqlc.narg(member_id), sqlc.arg(token_hash), sqlc.arg(expires_at), sqlc.narg(ip), sqlc.narg(user_agent), COALESCE(sqlc.narg(auth_time), now()), COALESCE(sqlc.narg(assurance_level), 1))
RETURNING id, user_id, member_id, token_hash, created_at, last_seen_at, expires_at, revoked_at, ip, user_agent, auth_time, assurance_level;

-- name: GetSession :one
SELECT id, user_id, member_id, token_hash, created_at, last_seen_at, expires_at, revoked_at, ip, user_agent, auth_time, assurance_level FROM sessions WHERE id = sqlc.arg(id);

-- name: RevokeSession :exec
UPDATE sessions SET revoked_at = COALESCE(revoked_at, now()) WHERE id = sqlc.arg(id);

-- name: RevokeUserSessions :exec
UPDATE sessions SET revoked_at = COALESCE(revoked_at, now()) WHERE user_id = sqlc.arg(user_id) AND revoked_at IS NULL;

-- name: RevokeUserRefreshTokens :exec
UPDATE refresh_tokens SET revoked_at = COALESCE(revoked_at, now())
WHERE session_id IN (SELECT id FROM sessions WHERE user_id = sqlc.arg(user_id));

-- name: SetSessionMember :exec
UPDATE sessions SET member_id = sqlc.narg(member_id), last_seen_at = now()
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id) AND revoked_at IS NULL;

-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (id, session_id, family_id, token_hash, expires_at)
VALUES (sqlc.arg(id), sqlc.arg(session_id), sqlc.arg(family_id), sqlc.arg(token_hash), sqlc.arg(expires_at))
RETURNING id, session_id, family_id, token_hash, issued_at, expires_at, used_at, revoked_at;

-- name: LockRefreshToken :one
SELECT id, session_id, family_id, token_hash, issued_at, expires_at, used_at, revoked_at FROM refresh_tokens WHERE token_hash = sqlc.arg(token_hash) FOR UPDATE;

-- name: MarkRefreshUsed :one
UPDATE refresh_tokens SET used_at = now()
WHERE id = sqlc.arg(id) AND used_at IS NULL AND revoked_at IS NULL AND expires_at > now()
RETURNING id;

-- name: RevokeRefreshFamily :exec
UPDATE refresh_tokens SET revoked_at = COALESCE(revoked_at, now()) WHERE family_id = sqlc.arg(family_id);

-- name: RevokeSessionRefreshTokens :exec
UPDATE refresh_tokens SET revoked_at = COALESCE(revoked_at, now()) WHERE session_id = sqlc.arg(session_id);
