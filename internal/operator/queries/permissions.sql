-- name: CreateCatalogPermission :one
INSERT INTO permissions (id, key, description, risk, principal_kinds, delegable, agent_approval)
VALUES (sqlc.arg(id), sqlc.arg(key), sqlc.arg(description), sqlc.arg(risk), sqlc.arg(principal_kinds), sqlc.arg(delegable), sqlc.arg(agent_approval))
ON CONFLICT (key) DO NOTHING
RETURNING id, key, description, risk, principal_kinds, delegable, agent_approval, status, created_at;

-- name: ListCatalogPermissions :many
SELECT id, key, description, risk, principal_kinds, delegable, agent_approval, status, created_at
FROM permissions
ORDER BY key;
