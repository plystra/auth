-- name: CreateDirectory :one
INSERT INTO directories (id, space_id, name, token_prefix, token_hash, configured_by_member_id, configured_by_user_id, sso_connection_id, sso_identity_claim)
VALUES (sqlc.arg(id), sqlc.arg(space_id), sqlc.arg(name), sqlc.arg(token_prefix), sqlc.arg(token_hash), sqlc.arg(configured_by_member_id), sqlc.narg(configured_by_user_id), sqlc.narg(sso_connection_id), sqlc.narg(sso_identity_claim))
RETURNING id, space_id, name, token_prefix, token_hash, status, version, created_at, updated_at, configured_by_member_id, configured_by_user_id, sso_connection_id, sso_identity_claim;

-- name: CreateDirectoryProvisionedUser :one
INSERT INTO users (id, email, email_normalized, password_hash, display_name, status, email_verified_at)
VALUES (sqlc.arg(id), sqlc.arg(email), sqlc.arg(email_normalized), sqlc.arg(password_hash), sqlc.arg(display_name), 'active', now())
RETURNING id, email, email_normalized, password_hash, email_verified_at, disabled_at, status, password_reset_required_at, created_at, updated_at;

-- name: GetDirectory :one
SELECT id, space_id, name, token_prefix, token_hash, status, version, created_at, updated_at, configured_by_member_id, configured_by_user_id, sso_connection_id, sso_identity_claim
FROM directories WHERE id = sqlc.arg(id);

-- name: ListDirectories :many
SELECT id, space_id, name, status, version, created_at, updated_at, sso_connection_id, sso_identity_claim
FROM directories WHERE space_id = sqlc.arg(space_id)
ORDER BY created_at, id;

-- name: LockDirectory :one
SELECT id, space_id, name, token_prefix, token_hash, status, version, created_at, updated_at, configured_by_member_id, configured_by_user_id, sso_connection_id, sso_identity_claim
FROM directories WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: GetDirectoryByTokenHash :one
SELECT id, space_id, name, token_prefix, token_hash, status, version, created_at, updated_at, configured_by_member_id, configured_by_user_id, sso_connection_id, sso_identity_claim
FROM directories WHERE token_hash = sqlc.arg(token_hash);

-- name: DisableDirectory :exec
UPDATE directories SET status = 'disabled', version = version + 1, updated_at = now()
WHERE id = sqlc.arg(id) AND status <> 'disabled';

-- name: UpdateDirectoryConfiguration :one
UPDATE directories SET name = sqlc.arg(name), sso_connection_id = sqlc.narg(sso_connection_id), sso_identity_claim = sqlc.narg(sso_identity_claim), version = version + 1, updated_at = now()
WHERE id = sqlc.arg(id) AND status = 'active' AND version = sqlc.arg(version)
RETURNING id, space_id, name, token_prefix, token_hash, status, version, created_at, updated_at, configured_by_member_id, configured_by_user_id, sso_connection_id, sso_identity_claim;

-- name: RotateDirectoryToken :one
UPDATE directories SET token_prefix = sqlc.arg(token_prefix), token_hash = sqlc.arg(token_hash),
    version = version + 1, updated_at = now(),
    configured_by_member_id = sqlc.arg(configured_by_member_id), configured_by_user_id = sqlc.narg(configured_by_user_id)
WHERE id = sqlc.arg(id) AND status = 'active' AND version = sqlc.arg(version)
RETURNING *;

-- name: CreateDirectoryUser :one
INSERT INTO directory_users (id, directory_id, external_id, user_id, member_id, user_name, display_name, active)
VALUES (sqlc.arg(id), sqlc.arg(directory_id), sqlc.arg(external_id), sqlc.arg(user_id), sqlc.arg(member_id), sqlc.arg(user_name), sqlc.arg(display_name), sqlc.arg(active))
RETURNING id, directory_id, external_id, user_id, member_id, user_name, display_name, active, version, created_at, updated_at, deleted_at;

-- name: GetDirectoryUserByExternalID :one
SELECT id, directory_id, external_id, user_id, member_id, user_name, display_name, active, version, created_at, updated_at, deleted_at
FROM directory_users WHERE directory_id = sqlc.arg(directory_id) AND external_id = sqlc.arg(external_id);

-- name: GetDirectoryUserByID :one
SELECT id, directory_id, external_id, user_id, member_id, user_name, display_name, active, version, created_at, updated_at, deleted_at
FROM directory_users WHERE directory_id = sqlc.arg(directory_id) AND id = sqlc.arg(id) AND deleted_at IS NULL;

-- name: LockDirectoryUser :one
SELECT id, directory_id, external_id, user_id, member_id, user_name, display_name, active, version, created_at, updated_at, deleted_at
FROM directory_users WHERE directory_id = sqlc.arg(directory_id) AND id = sqlc.arg(id) AND deleted_at IS NULL FOR UPDATE;

-- name: ListDirectoryUsers :many
SELECT id, directory_id, external_id, user_id, member_id, user_name, display_name, active, version, created_at, updated_at, deleted_at
FROM directory_users
WHERE directory_id = sqlc.arg(directory_id) AND deleted_at IS NULL
  AND (sqlc.arg(filter_user_name)::text = '' OR user_name = sqlc.arg(filter_user_name))
  AND (sqlc.arg(filter_external_id)::text = '' OR external_id = sqlc.arg(filter_external_id))
ORDER BY id
LIMIT sqlc.arg(limit_count) OFFSET sqlc.arg(offset_count);

-- name: CountDirectoryUsers :one
SELECT count(*)::bigint FROM directory_users
WHERE directory_id = sqlc.arg(directory_id) AND deleted_at IS NULL
  AND (sqlc.arg(filter_user_name)::text = '' OR user_name = sqlc.arg(filter_user_name))
  AND (sqlc.arg(filter_external_id)::text = '' OR external_id = sqlc.arg(filter_external_id));

-- name: UpdateDirectoryUser :one
UPDATE directory_users SET user_name = sqlc.arg(user_name), display_name = sqlc.arg(display_name),
    active = sqlc.arg(active), version = version + 1, updated_at = now()
WHERE directory_id = sqlc.arg(directory_id) AND id = sqlc.arg(id) AND version = sqlc.arg(version)
RETURNING id, directory_id, external_id, user_id, member_id, user_name, display_name, active, version, created_at, updated_at, deleted_at;

-- name: UpdateDirectoryUserEmail :exec
UPDATE users SET email = sqlc.arg(email), email_normalized = sqlc.arg(email_normalized), updated_at = now()
WHERE users.id = (SELECT user_id FROM directory_users WHERE directory_id = sqlc.arg(directory_id) AND directory_users.id = sqlc.arg(id));

-- name: UpdateDirectoryUserProfile :exec
UPDATE users SET display_name = sqlc.arg(display_name), updated_at = now()
WHERE users.id = (SELECT user_id FROM directory_users WHERE directory_id = sqlc.arg(directory_id) AND directory_users.id = sqlc.arg(id));

-- name: TombstoneDirectoryUser :one
UPDATE directory_users SET active = false, deleted_at = now(), version = version + 1, updated_at = now()
WHERE directory_id = sqlc.arg(directory_id) AND id = sqlc.arg(id) AND version = sqlc.arg(version)
RETURNING id, directory_id, external_id, user_id, member_id, user_name, display_name, active, version, created_at, updated_at, deleted_at;

-- name: CreateDirectoryGroup :one
INSERT INTO directory_groups (id, directory_id, external_id, group_id, display_name)
VALUES (sqlc.arg(id), sqlc.arg(directory_id), sqlc.arg(external_id), sqlc.arg(group_id), sqlc.arg(display_name))
RETURNING id, directory_id, external_id, group_id, display_name, version, created_at, updated_at, deleted_at;

-- name: GetDirectoryGroupByExternalID :one
SELECT id, directory_id, external_id, group_id, display_name, version, created_at, updated_at, deleted_at
FROM directory_groups WHERE directory_id = sqlc.arg(directory_id) AND external_id = sqlc.arg(external_id);

-- name: GetDirectoryGroupByID :one
SELECT id, directory_id, external_id, group_id, display_name, version, created_at, updated_at, deleted_at
FROM directory_groups WHERE directory_id = sqlc.arg(directory_id) AND id = sqlc.arg(id) AND deleted_at IS NULL;

-- name: IsDirectoryBackedGroup :one
SELECT EXISTS (SELECT 1 FROM directory_groups WHERE group_id = sqlc.arg(group_id));

-- name: ListDirectoryGroupMappings :many
SELECT dg.id, dg.group_id, dg.display_name
FROM directory_groups dg
JOIN groups g ON g.id = dg.group_id AND g.space_id = sqlc.arg(space_id) AND g.status = 'active'
WHERE dg.directory_id = sqlc.arg(directory_id) AND dg.deleted_at IS NULL
  AND dg.id > sqlc.arg(after_id)
ORDER BY dg.id
LIMIT sqlc.arg(limit_count);

-- name: LockDirectoryGroup :one
SELECT id, directory_id, external_id, group_id, display_name, version, created_at, updated_at, deleted_at
FROM directory_groups WHERE directory_id = sqlc.arg(directory_id) AND id = sqlc.arg(id) AND deleted_at IS NULL FOR UPDATE;

-- name: ListDirectoryGroups :many
SELECT id, directory_id, external_id, group_id, display_name, version, created_at, updated_at, deleted_at
FROM directory_groups WHERE directory_id = sqlc.arg(directory_id) AND deleted_at IS NULL
  AND (sqlc.arg(filter_display_name)::text = '' OR lower(display_name) = lower(sqlc.arg(filter_display_name)))
  AND (sqlc.arg(filter_external_id)::text = '' OR external_id = sqlc.arg(filter_external_id))
ORDER BY id LIMIT sqlc.arg(limit_count) OFFSET sqlc.arg(offset_count);

-- name: CountDirectoryGroups :one
SELECT count(*)::bigint FROM directory_groups WHERE directory_id = sqlc.arg(directory_id) AND deleted_at IS NULL
  AND (sqlc.arg(filter_display_name)::text = '' OR lower(display_name) = lower(sqlc.arg(filter_display_name)))
  AND (sqlc.arg(filter_external_id)::text = '' OR external_id = sqlc.arg(filter_external_id));

-- name: UpdateDirectoryGroup :one
UPDATE directory_groups SET display_name = sqlc.arg(display_name), version = version + 1, updated_at = now()
WHERE directory_id = sqlc.arg(directory_id) AND id = sqlc.arg(id) AND version = sqlc.arg(version)
RETURNING id, directory_id, external_id, group_id, display_name, version, created_at, updated_at, deleted_at;

-- name: DeleteDirectoryGroup :exec
UPDATE directory_groups SET deleted_at = now(), version = version + 1, updated_at = now() WHERE directory_id = sqlc.arg(directory_id) AND id = sqlc.arg(id) AND deleted_at IS NULL AND version = sqlc.arg(version);

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

-- name: LockDirectoryForRead :one
SELECT * FROM directories WHERE id = sqlc.arg(id) FOR SHARE;

-- name: ListDirectoryUsersForLock :many
SELECT du.user_id, du.member_id FROM directory_users du WHERE du.directory_id = sqlc.arg(directory_id)
UNION
SELECT coalesce(um.user_id, '')::text AS user_id, gm.member_id
FROM directory_groups dg JOIN group_members gm ON gm.group_id = dg.group_id
LEFT JOIN user_members um ON um.member_id = gm.member_id
WHERE dg.directory_id = sqlc.arg(directory_id) AND dg.deleted_at IS NULL
ORDER BY user_id, member_id;

-- name: GetSCIMStandardRoot :one
SELECT id, status FROM groups WHERE space_id = sqlc.arg(space_id)
AND kind = 'standard' AND parent_id IS NULL AND status <> 'removed';

-- name: RenameDirectoryBackedGroup :exec
UPDATE groups SET name = sqlc.arg(name) WHERE id = sqlc.arg(id) AND space_id = sqlc.arg(space_id);

-- name: CountLiveGroupChildren :one
SELECT count(*)::bigint FROM groups WHERE parent_id = sqlc.arg(group_id) AND status <> 'removed';

-- name: ListDirectoryBackedGroupMembers :many
SELECT member_id FROM group_members WHERE group_id = sqlc.arg(group_id) ORDER BY member_id;

-- name: GetDirectoryForSSOConnection :one
SELECT * FROM directories WHERE sso_connection_id = sqlc.arg(connection_id)
ORDER BY (status = 'active') DESC, id LIMIT 1;

-- name: GetDirectoryLoginIdentity :one
SELECT du.id AS directory_user_id, du.user_id, du.member_id, u.email, u.display_name, u.status, u.created_at
FROM directory_users du
JOIN users u ON u.id = du.user_id
JOIN members m ON m.id = du.member_id AND m.space_id = sqlc.arg(space_id)
JOIN user_members um ON um.user_id = du.user_id AND um.member_id = du.member_id
WHERE du.directory_id = sqlc.arg(directory_id) AND du.id = sqlc.arg(id)
  AND du.active AND du.deleted_at IS NULL AND u.status = 'active' AND u.disabled_at IS NULL
  AND m.type = 'human' AND m.status = 'active'
  AND um.status = 'active' AND um.revoked_at IS NULL
  AND (um.expires_at IS NULL OR um.expires_at > clock_timestamp());
