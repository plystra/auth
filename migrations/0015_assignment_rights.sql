-- +goose Up

CREATE TABLE assign_rights (
    id text PRIMARY KEY CHECK (left(id, 3) = 'ar_'),
    holder_member_id text NOT NULL REFERENCES members(id) ON DELETE CASCADE,
    permission_keys jsonb NOT NULL
        CHECK (CASE WHEN jsonb_typeof(permission_keys) = 'array'
            THEN jsonb_array_length(permission_keys) > 0 ELSE false END),
    anchor_space_id text REFERENCES spaces(id) ON DELETE CASCADE,
    anchor_group_id text REFERENCES groups(id) ON DELETE CASCADE,
    covers_subtree boolean NOT NULL DEFAULT false,
    can_redelegate boolean NOT NULL DEFAULT false,
    source text NOT NULL CHECK (source IN ('system', 'operator', 'delegated')),
    parent_id text REFERENCES assign_rights(id),
    granted_by_operator_user_id text REFERENCES operators(user_id),
    expires_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((anchor_space_id IS NOT NULL) <> (anchor_group_id IS NOT NULL)),
    CHECK (parent_id IS DISTINCT FROM id),
    CHECK (expires_at IS NULL OR expires_at > created_at),
    CHECK (
        (source = 'system' AND parent_id IS NULL AND granted_by_operator_user_id IS NULL)
        OR (source = 'operator' AND parent_id IS NULL AND granted_by_operator_user_id IS NOT NULL)
        OR (source = 'delegated' AND parent_id IS NOT NULL AND granted_by_operator_user_id IS NULL)
    )
);

CREATE INDEX assign_rights_holder_active_idx
    ON assign_rights(holder_member_id, expires_at)
    WHERE revoked_at IS NULL;

CREATE INDEX assign_rights_anchor_space_idx
    ON assign_rights(anchor_space_id)
    WHERE anchor_space_id IS NOT NULL AND revoked_at IS NULL;

CREATE INDEX assign_rights_anchor_group_idx
    ON assign_rights(anchor_group_id)
    WHERE anchor_group_id IS NOT NULL AND revoked_at IS NULL;

-- +goose Down
-- Forward-only migration: use a compensating migration if rollback is required.
