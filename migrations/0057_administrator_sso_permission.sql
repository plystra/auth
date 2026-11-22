-- +goose Up

-- Every Space administrator must be able to configure enterprise login. The
-- operation still requires human step-up and the authorization engine, while
-- Agent use remains subject to the catalog's approval rule.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON p.key = 'auth.connections:manage'
WHERE r.name = 'administrator' AND r.managed = true
ON CONFLICT DO NOTHING;

-- +goose Down
-- Forward-only migration: add a compensating migration if removal is required.
