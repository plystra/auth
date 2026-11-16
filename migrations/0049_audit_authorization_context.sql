-- +goose Up

-- Authorization identities are immutable event snapshots, not foreign keys:
-- deleting credentials or tombstoning members must not erase audit evidence.
-- Historical rows keep empty context; do not infer past identities from today.
-- Resource locations are request facts and can be malformed in denied requests;
-- only verified identity columns enforce typed ID prefixes.
ALTER TABLE audit_logs
    ADD COLUMN plane text NOT NULL DEFAULT '',
    ADD COLUMN credential_type text NOT NULL DEFAULT '',
    ADD COLUMN space_id text,
    ADD COLUMN resource_group_id text,
    ADD COLUMN member_id text CHECK (member_id IS NULL OR left(member_id, 4) = 'mem_'),
    ADD COLUMN member_type text CHECK (member_type IN ('human', 'agent', 'application')),
    ADD COLUMN user_id text CHECK (user_id IS NULL OR left(user_id, 4) = 'usr_'),
    ADD COLUMN application_id text CHECK (application_id IS NULL OR left(application_id, 4) = 'app_'),
    ADD COLUMN owner_chain jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(owner_chain) = 'array'),
    ADD COLUMN decision_id text CHECK (decision_id IS NULL OR left(decision_id, 4) = 'dec_'),
    ADD COLUMN deny_code text,
    ADD COLUMN permission_key text,
    ADD COLUMN policy_version bigint,
    ADD CONSTRAINT audit_member_identity_check CHECK ((member_id IS NULL) = (member_type IS NULL));

CREATE INDEX audit_logs_space_cursor_idx ON audit_logs(space_id, occurred_at DESC, id DESC);
CREATE INDEX audit_logs_member_cursor_idx ON audit_logs(member_id, occurred_at DESC, id DESC);
CREATE INDEX audit_logs_decision_idx ON audit_logs(decision_id) WHERE decision_id IS NOT NULL;

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
