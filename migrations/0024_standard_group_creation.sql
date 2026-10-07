-- +goose Up

-- Existing administrator roles must retain the built-in permission required by
-- the standard-group management endpoint introduced after the initial seed.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'administrator' AND p.key = 'auth.groups:manage'
ON CONFLICT DO NOTHING;

-- +goose Down
-- Forward-only migration: replace this migration with a compensating migration.
