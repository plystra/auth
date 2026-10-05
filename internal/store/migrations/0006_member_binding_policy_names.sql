-- +goose Up

ALTER TABLE members DROP CONSTRAINT IF EXISTS members_binding_policy_check;
ALTER TABLE members DROP CONSTRAINT IF EXISTS members_agent_fields_check;
UPDATE members SET binding_policy = 'single' WHERE binding_policy = 'individual';
ALTER TABLE members ALTER COLUMN binding_policy SET DEFAULT 'single';
ALTER TABLE members ADD CONSTRAINT members_binding_policy_check CHECK (binding_policy IN ('single', 'shared'));
ALTER TABLE members ADD CONSTRAINT members_agent_fields_check CHECK (
    (type = 'agent' AND home_group_id IS NOT NULL AND binding_policy = 'single' AND created_by_member_id IS NOT NULL)
    OR (type <> 'agent' AND home_group_id IS NULL)
);

-- +goose Down
-- Forward-only migration: restore from a PostgreSQL backup or add a compensating migration.
