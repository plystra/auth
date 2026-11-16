-- +goose Up
-- Business data belongs to the SaaS database, separate from Auth's database.
CREATE TABLE invoices (
    id text PRIMARY KEY CHECK (id ~ '^inv_[a-zA-Z0-9_-]+$'),
    space_id text NOT NULL CHECK (space_id LIKE 'spc\_%'),
    group_id text NOT NULL CHECK (group_id LIKE 'grp\_%'),
    amount_cents bigint NOT NULL CHECK (amount_cents > 0),
    currency text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    status text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'approved')),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    approved_by text CHECK (approved_by LIKE 'mem\_%'),
    approved_at timestamptz,
    CHECK ((status = 'draft' AND approved_by IS NULL AND approved_at IS NULL)
        OR (status = 'approved' AND approved_by IS NOT NULL AND approved_at IS NOT NULL))
);
