-- +goose Up

CREATE TABLE operator_sessions (
    id text PRIMARY KEY CHECK (id ~ '^ops_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    user_id text NOT NULL REFERENCES operators(user_id) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    idle_expires_at timestamptz NOT NULL,
    access_expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    assurance_level smallint NOT NULL DEFAULT 1 CHECK (assurance_level BETWEEN 1 AND 3),
    step_up_operation text,
    step_up_digest bytea,
    step_up_expires_at timestamptz,
    ip text,
    user_agent text
);
CREATE INDEX operator_sessions_active_idx ON operator_sessions(user_id, expires_at) WHERE revoked_at IS NULL;
