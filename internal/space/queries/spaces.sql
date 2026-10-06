-- name: CreateSpace :one
INSERT INTO spaces (id, name, slug, parent_id) VALUES (sqlc.arg(id), sqlc.arg(name), sqlc.arg(slug), sqlc.narg(parent_id)) RETURNING *;

-- name: GetSpace :one
SELECT * FROM spaces WHERE id = sqlc.arg(id);

-- name: ListChildSpaces :many
SELECT * FROM spaces
WHERE parent_id = sqlc.arg(parent_id) ORDER BY created_at, id;

-- name: BumpPolicyVersion :one
UPDATE spaces SET policy_version = policy_version + 1 WHERE id = sqlc.arg(id) RETURNING policy_version;
