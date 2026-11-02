-- +goose Up

CREATE TABLE application_installations (
    id text PRIMARY KEY CHECK (id LIKE 'ins_%'),
    application_id text NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    space_id text NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    member_id text NOT NULL UNIQUE REFERENCES members(id) ON DELETE CASCADE,
    role_id text NOT NULL UNIQUE REFERENCES roles(id) ON DELETE CASCADE,
    scope text NOT NULL CHECK (scope IN ('space', 'space_tree', 'group', 'group_tree')),
    anchor_group_id text REFERENCES groups(id),
    approved_permissions jsonb NOT NULL CHECK (jsonb_typeof(approved_permissions) = 'array'),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'uninstalled')),
    installed_by text NOT NULL REFERENCES members(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((scope IN ('group', 'group_tree')) = (anchor_group_id IS NOT NULL))
);

CREATE UNIQUE INDEX application_installations_current_unique
    ON application_installations (application_id, space_id)
    WHERE status <> 'uninstalled';

CREATE INDEX application_installations_application_idx
    ON application_installations (application_id, status);

-- +goose Down
-- Forward-only migrations: add a compensating migration if rollback is required.
