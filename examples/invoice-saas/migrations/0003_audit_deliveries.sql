-- +goose Up
-- Durable application-reported events contain identifiers and digests only.
-- The River job is inserted in the same business transaction. Auth receipts
-- are separate from the SaaS commit and never replace an authorization check.
CREATE TABLE invoice_audit_deliveries (
    id text PRIMARY KEY CHECK (id ~ '^evt_[0-9A-HJKMNP-TV-Z]{26}$'),
    invoice_id text NOT NULL REFERENCES invoices(id),
    space_id text NOT NULL CHECK (space_id LIKE 'spc\_%'),
    group_id text NOT NULL CHECK (group_id LIKE 'grp\_%'),
    member_id text NOT NULL CHECK (member_id LIKE 'mem\_%'),
    user_id text CHECK (user_id LIKE 'usr\_%'),
    action text NOT NULL CHECK (action IN ('invoice.read', 'invoice.approve')),
    outcome text NOT NULL CHECK (outcome IN ('success', 'failure', 'deny')),
    request_id text NOT NULL CHECK (length(request_id) BETWEEN 1 AND 128),
    request_digest text CHECK (request_digest ~ '^[a-f0-9]{64}$'),
    created_at timestamptz NOT NULL DEFAULT now(),
    river_job_id bigint UNIQUE,
    generation integer NOT NULL DEFAULT 0 CHECK (generation >= 0),
    attempt_started_at timestamptz,
    destination_hash bytea CHECK (octet_length(destination_hash) = 32),
    audit_id text UNIQUE CHECK (audit_id LIKE 'aud\_%'),
    delivered_at timestamptz,
    last_error text CHECK (last_error IN ('AUTH_UNAVAILABLE', 'AUTH_REJECTED', 'INVALID_RECEIPT',
        'IDEMPOTENCY_WINDOW_EXPIRED', 'DESTINATION_CHANGED')),
    blocked boolean NOT NULL DEFAULT false,
    CHECK ((attempt_started_at IS NULL) = (destination_hash IS NULL)),
    CHECK ((audit_id IS NULL) = (delivered_at IS NULL)),
    CHECK (NOT blocked OR (audit_id IS NULL AND last_error IS NOT NULL))
);

CREATE INDEX invoice_audit_delivery_pending ON invoice_audit_deliveries(created_at, id)
WHERE audit_id IS NULL;
