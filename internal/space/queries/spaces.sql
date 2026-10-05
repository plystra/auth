-- name: CreateSpace :one
INSERT INTO spaces (id, name, slug, parent_id) VALUES (sqlc.arg(id), sqlc.arg(name), sqlc.arg(slug), sqlc.narg(parent_id)) RETURNING id, name, slug, parent_id, policy_version, created_at;

-- name: GetSpace :one
SELECT id, name, slug, parent_id, policy_version, created_at FROM spaces WHERE id = sqlc.arg(id);

-- name: BumpPolicyVersion :one
UPDATE spaces SET policy_version = policy_version + 1 WHERE id = sqlc.arg(id) RETURNING policy_version;
