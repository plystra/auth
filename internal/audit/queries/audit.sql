-- name: AppendAudit :exec
INSERT INTO audit_logs (id, actor_type, actor_id, action, resource_type, resource_id, outcome, request_id, metadata, plane, credential_type)
VALUES (sqlc.arg(id), sqlc.arg(actor_type), sqlc.narg(actor_id), sqlc.arg(action), sqlc.narg(resource_type), sqlc.narg(resource_id), sqlc.arg(outcome), sqlc.narg(request_id), COALESCE(sqlc.narg(metadata), '{}'::jsonb), sqlc.arg(plane), sqlc.arg(credential_type));

-- name: GetAuditMemberChain :many
WITH RECURSIVE chain AS (
    SELECT m.id, m.space_id, m.type AS member_type, g.owner_member_id,
           0 AS depth, ARRAY[m.id] AS visited
    FROM members m LEFT JOIN groups g ON g.id = m.home_group_id AND g.kind = 'agents'
    WHERE m.id = sqlc.arg(member_id)
    UNION ALL
    SELECT m.id, m.space_id, m.type, g.owner_member_id,
           c.depth + 1, c.visited || m.id
    FROM chain c
    JOIN members m ON m.id = c.owner_member_id AND m.space_id = c.space_id
    LEFT JOIN groups g ON g.id = m.home_group_id AND g.kind = 'agents'
    WHERE c.member_type = 'agent' AND c.depth < 64 AND NOT m.id = ANY(c.visited)
)
SELECT id, space_id, member_type FROM chain ORDER BY depth;

-- name: AppendAuthorizationDecisionAudit :exec
INSERT INTO audit_logs (
    id, actor_type, actor_id, action, resource_type, resource_id, outcome, request_id, metadata,
    plane, credential_type, space_id, resource_group_id, member_id, member_type, user_id,
    application_id, owner_chain, decision_id, deny_code, permission_key, policy_version
)
VALUES (
    sqlc.arg(id), 'application', sqlc.arg(key_id), sqlc.arg(action), sqlc.narg(resource_type),
    sqlc.narg(resource_id), 'deny', sqlc.narg(request_id), sqlc.arg(metadata),
    sqlc.arg(plane), 'application', sqlc.narg(space_id), sqlc.narg(resource_group_id),
    sqlc.narg(member_id), sqlc.narg(member_type), sqlc.narg(user_id), sqlc.arg(application_id),
    sqlc.arg(owner_chain), sqlc.arg(decision_id), sqlc.arg(deny_code), sqlc.arg(permission_key), sqlc.arg(policy_version)
);

-- name: ListAudit :many
SELECT id, occurred_at, actor_type, actor_id, action, resource_type, resource_id, outcome, request_id, metadata FROM audit_logs ORDER BY occurred_at DESC LIMIT sqlc.arg(limit_count) OFFSET sqlc.arg(offset_count);

-- name: ListAuditGroups :many
SELECT id FROM groups
WHERE space_id = sqlc.arg(space_id)
  AND (sqlc.narg(group_id)::text IS NULL OR id = sqlc.narg(group_id))
ORDER BY id;

-- name: GetSpaceAuditCursor :one
SELECT occurred_at FROM audit_logs
WHERE id = sqlc.arg(id) AND space_id = sqlc.arg(space_id)
  AND ((resource_group_id IS NULL AND sqlc.arg(include_space_events)::boolean)
       OR resource_group_id = ANY(sqlc.arg(visible_group_ids)::text[]));

-- name: ListSpaceAudit :many
SELECT * FROM audit_logs
WHERE space_id = sqlc.arg(space_id)
  AND ((resource_group_id IS NULL AND sqlc.arg(include_space_events)::boolean)
       OR resource_group_id = ANY(sqlc.arg(visible_group_ids)::text[]))
  AND (sqlc.narg(cursor_at)::timestamptz IS NULL
       OR (occurred_at, id) < (sqlc.narg(cursor_at)::timestamptz, sqlc.narg(cursor_id)::text))
  AND (sqlc.narg(action)::text IS NULL OR action = sqlc.narg(action))
  AND (sqlc.narg(decision_id)::text IS NULL OR decision_id = sqlc.narg(decision_id))
  AND (sqlc.narg(request_id)::text IS NULL OR request_id = sqlc.narg(request_id))
  AND (sqlc.narg(member_id)::text IS NULL OR member_id = sqlc.narg(member_id)
       OR owner_chain @> jsonb_build_array(jsonb_build_object('member_id', sqlc.narg(member_id)::text)))
ORDER BY occurred_at DESC, id DESC
LIMIT sqlc.arg(limit_count);
