-- +goose Up

CREATE TABLE approval_requests (
    id text PRIMARY KEY CHECK (left(id, 4) = 'apr_'),
    agent_member_id text NOT NULL REFERENCES members(id),
    approver_member_id text NOT NULL REFERENCES members(id),
    permission_key text NOT NULL,
    resource_type text NOT NULL CHECK (resource_type <> ''),
    resource_id text NOT NULL CHECK (resource_id <> ''),
    resource_space_id text NOT NULL REFERENCES spaces(id),
    resource_group_id text,
    resource_owner_member_id text,
    request_digest bytea NOT NULL CHECK (length(request_digest) = 32),
    reason text NOT NULL DEFAULT '',
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'rejected', 'consumed')),
    expires_at timestamptz NOT NULL,
    decided_by_user_id text REFERENCES users(id),
    decided_at timestamptz,
    approved_expires_at timestamptz,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((status = 'pending' AND decided_by_user_id IS NULL AND decided_at IS NULL)
        OR (status <> 'pending' AND decided_by_user_id IS NOT NULL AND decided_at IS NOT NULL))
);

CREATE INDEX approval_requests_inbox_idx
    ON approval_requests (approver_member_id, created_at DESC)
    WHERE status = 'pending';

CREATE INDEX approval_requests_approved_idx
    ON approval_requests (agent_member_id, permission_key, resource_space_id, created_at DESC)
    WHERE status = 'approved';

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
