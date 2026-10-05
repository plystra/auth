-- +goose Up

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'active'
        CHECK (status IN ('pending', 'active', 'suspended', 'disabled'));

UPDATE users SET status = 'disabled' WHERE disabled_at IS NOT NULL AND status = 'active';

INSERT INTO permissions (id, key, description)
VALUES ('prm_01h00000000000000000000012', 'auth.bindings:manage', 'Bind and revoke users on members')
ON CONFLICT (key) DO UPDATE SET description = EXCLUDED.description;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'administrator' AND p.key = 'auth.bindings:manage'
ON CONFLICT DO NOTHING;

-- +goose Down
-- Forward-only migrations: add a compensating migration if rollback is required.
