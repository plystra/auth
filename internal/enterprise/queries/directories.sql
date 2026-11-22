-- name: CreateDirectory :one
INSERT INTO directories (id, space_id, name, token_prefix, token_hash)
VALUES (sqlc.arg(id), sqlc.arg(space_id), sqlc.arg(name), sqlc.arg(token_prefix), sqlc.arg(token_hash))
RETURNING id, space_id, name, token_prefix, token_hash, status, version, created_at, updated_at;

-- name: CreateDirectoryProvisionedUser :one
INSERT INTO users (id, email, email_normalized, password_hash, status, email_verified_at)
VALUES (sqlc.arg(id), sqlc.arg(email), sqlc.arg(email_normalized), sqlc.arg(password_hash), 'active', now())
RETURNING id, email, email_normalized, password_hash, email_verified_at, disabled_at, status, password_reset_required_at, created_at, updated_at;

-- name: GetDirectory :one
SELECT id, space_id, name, token_prefix, token_hash, status, version, created_at, updated_at
FROM directories WHERE id = sqlc.arg(id);

-- name: ListDirectories :many
SELECT id, space_id, name, token_prefix, status, version, created_at, updated_at
FROM directories WHERE space_id = sqlc.arg(space_id)
ORDER BY created_at, id;

-- name: LockDirectory :one
SELECT id, space_id, name, token_prefix, token_hash, status, version, created_at, updated_at
FROM directories WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: GetDirectoryByTokenHash :one
SELECT id, space_id, name, token_prefix, token_hash, status, version, created_at, updated_at
FROM directories WHERE token_hash = sqlc.arg(token_hash);

-- name: DisableDirectory :exec
UPDATE directories SET status = 'disabled', version = version + 1, updated_at = now()
WHERE id = sqlc.arg(id) AND status <> 'disabled';

-- name: UpdateDirectoryName :one
UPDATE directories SET name = sqlc.arg(name), version = version + 1, updated_at = now()
WHERE id = sqlc.arg(id) AND status = 'active' AND version = sqlc.arg(version)
RETURNING id, space_id, name, token_prefix, token_hash, status, version, created_at, updated_at;

-- name: RotateDirectoryToken :exec
UPDATE directories SET token_prefix = sqlc.arg(token_prefix), token_hash = sqlc.arg(token_hash),
    version = version + 1, updated_at = now()
WHERE id = sqlc.arg(id) AND status = 'active' AND version = sqlc.arg(version);

-- name: CreateDirectoryUser :one
INSERT INTO directory_users (id, directory_id, external_id, user_id, member_id, user_name, display_name)
VALUES (sqlc.arg(id), sqlc.arg(directory_id), sqlc.arg(external_id), sqlc.arg(user_id), sqlc.arg(member_id), sqlc.arg(user_name), sqlc.arg(display_name))
RETURNING id, directory_id, external_id, user_id, member_id, user_name, display_name, active, version, created_at, updated_at;

-- name: GetDirectoryUserByExternalID :one
SELECT id, directory_id, external_id, user_id, member_id, user_name, display_name, active, version, created_at, updated_at
FROM directory_users WHERE directory_id = sqlc.arg(directory_id) AND external_id = sqlc.arg(external_id);

-- name: GetDirectoryUserByID :one
SELECT id, directory_id, external_id, user_id, member_id, user_name, display_name, active, version, created_at, updated_at
FROM directory_users WHERE directory_id = sqlc.arg(directory_id) AND id = sqlc.arg(id);

-- name: LockDirectoryUser :one
SELECT id, directory_id, external_id, user_id, member_id, user_name, display_name, active, version, created_at, updated_at
FROM directory_users WHERE directory_id = sqlc.arg(directory_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: ListDirectoryUsers :many
SELECT id, directory_id, external_id, user_id, member_id, user_name, display_name, active, version, created_at, updated_at
FROM directory_users
WHERE directory_id = sqlc.arg(directory_id)
  AND (sqlc.arg(filter_user_name)::text = '' OR user_name = sqlc.arg(filter_user_name))
ORDER BY id
LIMIT sqlc.arg(limit_count) OFFSET sqlc.arg(offset_count);

-- name: CountDirectoryUsers :one
SELECT count(*)::bigint FROM directory_users
WHERE directory_id = sqlc.arg(directory_id)
  AND (sqlc.arg(filter_user_name)::text = '' OR user_name = sqlc.arg(filter_user_name));

-- name: UpdateDirectoryUser :one
UPDATE directory_users SET user_name = sqlc.arg(user_name), display_name = sqlc.arg(display_name),
    active = sqlc.arg(active), version = version + 1, updated_at = now()
WHERE directory_id = sqlc.arg(directory_id) AND id = sqlc.arg(id) AND version = sqlc.arg(version)
RETURNING id, directory_id, external_id, user_id, member_id, user_name, display_name, active, version, created_at, updated_at;

-- name: UpdateDirectoryUserEmail :exec
UPDATE users SET email = sqlc.arg(email), email_normalized = sqlc.arg(email_normalized), updated_at = now()
WHERE users.id = (SELECT user_id FROM directory_users WHERE directory_id = sqlc.arg(directory_id) AND directory_users.id = sqlc.arg(id));

-- name: UpdateDirectoryUserProfile :exec
UPDATE users SET display_name = sqlc.arg(display_name), updated_at = now()
WHERE users.id = (SELECT user_id FROM directory_users WHERE directory_id = sqlc.arg(directory_id) AND directory_users.id = sqlc.arg(id));

-- name: TombstoneDirectoryUser :one
UPDATE directory_users SET active = false, version = version + 1, updated_at = now()
WHERE directory_id = sqlc.arg(directory_id) AND id = sqlc.arg(id) AND version = sqlc.arg(version)
RETURNING id, directory_id, external_id, user_id, member_id, user_name, display_name, active, version, created_at, updated_at;

-- name: CreateDirectoryGroup :one
INSERT INTO directory_groups (id, directory_id, external_id, group_id, display_name)
VALUES (sqlc.arg(id), sqlc.arg(directory_id), sqlc.arg(external_id), sqlc.arg(group_id), sqlc.arg(display_name))
RETURNING id, directory_id, external_id, group_id, display_name, version, created_at, updated_at;

-- name: GetDirectoryGroupByExternalID :one
SELECT id, directory_id, external_id, group_id, display_name, version, created_at, updated_at
FROM directory_groups WHERE directory_id = sqlc.arg(directory_id) AND external_id = sqlc.arg(external_id);

-- name: GetDirectoryGroupByID :one
SELECT id, directory_id, external_id, group_id, display_name, version, created_at, updated_at
FROM directory_groups WHERE directory_id = sqlc.arg(directory_id) AND id = sqlc.arg(id);

-- name: LockDirectoryGroup :one
SELECT id, directory_id, external_id, group_id, display_name, version, created_at, updated_at
FROM directory_groups WHERE directory_id = sqlc.arg(directory_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: ListDirectoryGroups :many
SELECT id, directory_id, external_id, group_id, display_name, version, created_at, updated_at
FROM directory_groups WHERE directory_id = sqlc.arg(directory_id)
ORDER BY id LIMIT sqlc.arg(limit_count) OFFSET sqlc.arg(offset_count);

-- name: CountDirectoryGroups :one
SELECT count(*)::bigint FROM directory_groups WHERE directory_id = sqlc.arg(directory_id);

-- name: UpdateDirectoryGroup :one
UPDATE directory_groups SET display_name = sqlc.arg(display_name), version = version + 1, updated_at = now()
WHERE directory_id = sqlc.arg(directory_id) AND id = sqlc.arg(id) AND version = sqlc.arg(version)
RETURNING id, directory_id, external_id, group_id, display_name, version, created_at, updated_at;

-- name: DeleteDirectoryGroup :exec
DELETE FROM directory_groups WHERE directory_id = sqlc.arg(directory_id) AND id = sqlc.arg(id) AND version = sqlc.arg(version);

-- name: ReplaceDirectoryGroupMembers :exec
WITH removed AS (
    DELETE FROM directory_group_members WHERE directory_group_id = sqlc.arg(directory_group_id)
)
INSERT INTO directory_group_members (directory_group_id, member_id)
SELECT sqlc.arg(directory_group_id), value::text
FROM jsonb_array_elements_text(sqlc.arg(member_ids)::jsonb)
ON CONFLICT DO NOTHING;

-- name: DeleteDirectoryGroupMembers :exec
DELETE FROM directory_group_members WHERE directory_group_id = sqlc.arg(directory_group_id);

-- name: DeleteDirectoryManagedGroupMembers :exec
DELETE FROM group_members
WHERE group_id = sqlc.arg(group_id) AND space_id = sqlc.arg(space_id) AND source = 'directory';

-- name: AddDirectoryGroupMember :exec
INSERT INTO directory_group_members (directory_group_id, member_id)
VALUES (sqlc.arg(directory_group_id), sqlc.arg(member_id))
ON CONFLICT DO NOTHING;

-- name: AddDirectoryManagedGroupMember :exec
INSERT INTO group_members (group_id, member_id, space_id, source)
VALUES (sqlc.arg(group_id), sqlc.arg(member_id), sqlc.arg(space_id), 'directory')
ON CONFLICT (group_id, member_id) DO NOTHING;

-- name: ListDirectoryGroupMemberIDs :many
SELECT member_id FROM directory_group_members WHERE directory_group_id = sqlc.arg(directory_group_id) ORDER BY member_id;

-- name: ListDirectoryGroupUserIDs :many
SELECT du.id
FROM directory_group_members dgm
JOIN directory_users du ON du.directory_id = sqlc.arg(directory_id) AND du.member_id = dgm.member_id
WHERE dgm.directory_group_id = sqlc.arg(directory_group_id)
ORDER BY du.id;

-- name: RemoveDirectoryBackedGroup :exec
UPDATE groups SET status = 'removed'
WHERE id = sqlc.arg(group_id) AND space_id = sqlc.arg(space_id);
