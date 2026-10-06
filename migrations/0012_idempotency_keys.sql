-- +goose Up

CREATE TABLE idempotency_keys (
    id text PRIMARY KEY CHECK (id LIKE 'idk_%'),
    scope_hash text NOT NULL,
    method text NOT NULL,
    path text NOT NULL,
    idempotency_key text NOT NULL,
    request_hash bytea NOT NULL,
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'completed')),
    status_code integer,
    response_headers jsonb NOT NULL DEFAULT '{}'::jsonb,
    response_body bytea,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    UNIQUE (scope_hash, method, path, idempotency_key)
);

CREATE INDEX idempotency_keys_expiry_idx ON idempotency_keys (expires_at);
