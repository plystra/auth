-- +goose Up

-- Agent-first authorization: agents are members with an immutable owner group.
-- Keep the legacy kind column during the migration window; type is the
-- canonical value used by new code and is intentionally never client supplied
-- for agent creation.
ALTER TABLE members ADD COLUMN IF NOT EXISTS type text;
UPDATE members
SET type = CASE kind
    WHEN 'user' THEN 'human'
    WHEN 'service' THEN 'application'
    ELSE kind
END
WHERE type IS NULL;
ALTER TABLE members ALTER COLUMN type SET DEFAULT 'human';
ALTER TABLE members ALTER COLUMN type SET NOT NULL;
ALTER TABLE members DROP CONSTRAINT IF EXISTS members_type_check;
ALTER TABLE members ADD CONSTRAINT members_type_check CHECK (type IN ('human', 'agent', 'application'));
ALTER TABLE members ADD COLUMN IF NOT EXISTS version bigint NOT NULL DEFAULT 1;
ALTER TABLE members ADD COLUMN IF NOT EXISTS metadata jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE members ADD COLUMN IF NOT EXISTS home_group_id text REFERENCES groups(id);
ALTER TABLE members ADD COLUMN IF NOT EXISTS created_by_user_id text REFERENCES users(id);
ALTER TABLE members ADD COLUMN IF NOT EXISTS created_by_member_id text REFERENCES members(id);
ALTER TABLE members ADD COLUMN IF NOT EXISTS source text;
ALTER TABLE members ADD COLUMN IF NOT EXISTS oauth_client_id text;
ALTER TABLE members ADD COLUMN IF NOT EXISTS expires_at timestamptz;
ALTER TABLE members ADD COLUMN IF NOT EXISTS deleted_at timestamptz;
ALTER TABLE members ADD CONSTRAINT members_agent_fields_check CHECK (
    (type = 'agent' AND home_group_id IS NOT NULL AND binding_policy = 'individual' AND created_by_member_id IS NOT NULL)
    OR (type <> 'agent' AND home_group_id IS NULL)
);
CREATE INDEX IF NOT EXISTS members_type_idx ON members(space_id, type, status);

ALTER TABLE groups ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'standard';
ALTER TABLE groups DROP CONSTRAINT IF EXISTS groups_kind_check;
ALTER TABLE groups ADD CONSTRAINT groups_kind_check CHECK (kind IN ('standard', 'agents'));
ALTER TABLE groups ADD COLUMN IF NOT EXISTS owner_member_id text REFERENCES members(id);
ALTER TABLE groups ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'active';
ALTER TABLE groups ADD CONSTRAINT groups_status_check CHECK (status IN ('active', 'suspended', 'removed'));
CREATE UNIQUE INDEX IF NOT EXISTS groups_agents_owner_unique
    ON groups(owner_member_id) WHERE kind = 'agents' AND status <> 'removed';
CREATE INDEX IF NOT EXISTS groups_owner_idx ON groups(owner_member_id) WHERE owner_member_id IS NOT NULL;

ALTER TABLE group_members ADD COLUMN IF NOT EXISTS source text NOT NULL DEFAULT 'manual';
ALTER TABLE group_members DROP CONSTRAINT IF EXISTS group_members_source_check;
ALTER TABLE group_members ADD CONSTRAINT group_members_source_check CHECK (source IN ('manual', 'directory', 'system'));

CREATE TABLE IF NOT EXISTS agent_credentials (
    id text PRIMARY KEY CHECK (id LIKE 'crd_%'),
    member_id text NOT NULL REFERENCES members(id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('key', 'oauth_refresh')),
    prefix text NOT NULL UNIQUE,
    secret_hash bytea NOT NULL UNIQUE,
    family_id text,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    last_used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS agent_credentials_active_idx
    ON agent_credentials(prefix) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS agent_credentials_member_idx
    ON agent_credentials(member_id, revoked_at);

ALTER TABLE permissions ADD COLUMN IF NOT EXISTS risk text NOT NULL DEFAULT 'low';
ALTER TABLE permissions ADD COLUMN IF NOT EXISTS principal_kinds jsonb NOT NULL DEFAULT '["human","agent","application"]'::jsonb;
ALTER TABLE permissions ADD COLUMN IF NOT EXISTS agent_approval text NOT NULL DEFAULT 'none';
ALTER TABLE permissions ADD CONSTRAINT permissions_risk_check CHECK (risk IN ('low', 'high', 'critical'));
ALTER TABLE permissions ADD CONSTRAINT permissions_agent_approval_check CHECK (agent_approval IN ('none', 'required'));

INSERT INTO permissions (id, key, description, principal_kinds, agent_approval, risk)
VALUES ('prm_01h00000000000000000000013', 'auth.agents:create', 'Create and manage Agent members', '["human","agent","application"]'::jsonb, 'none', 'high')
ON CONFLICT (key) DO UPDATE SET description = EXCLUDED.description,
    principal_kinds = EXCLUDED.principal_kinds, agent_approval = EXCLUDED.agent_approval, risk = EXCLUDED.risk;
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'administrator' AND p.key = 'auth.agents:create'
ON CONFLICT DO NOTHING;

-- Existing records are human members. The legacy kind remains a compatibility
-- mirror until all clients consume members.type.
UPDATE members SET type = 'human' WHERE type = 'user';

-- +goose Down
-- Forward-only migration: restore from a PostgreSQL backup or add a compensating migration.
