-- +goose Up

-- Audit queries correlate a member with events from its delegated descendants.
-- Snapshots remain immutable; this index does not reconstruct historical chains.
CREATE INDEX audit_logs_owner_chain_idx ON audit_logs USING gin(owner_chain jsonb_path_ops);

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
