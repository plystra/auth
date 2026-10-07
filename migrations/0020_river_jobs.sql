-- +goose Up

-- River's PostgreSQL schema is kept in the application's forward-only
-- migration stream so the queue is created by the same migration owner as
-- the rest of the Auth database.
CREATE TYPE river_job_state AS ENUM (
    'available',
    'cancelled',
    'completed',
    'discarded',
    'pending',
    'retryable',
    'running',
    'scheduled'
);

CREATE TABLE river_job (
    id bigserial PRIMARY KEY,
    state river_job_state NOT NULL DEFAULT 'available',
    attempt smallint NOT NULL DEFAULT 0,
    max_attempts smallint NOT NULL DEFAULT 25,
    attempted_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    finalized_at timestamptz,
    scheduled_at timestamptz NOT NULL DEFAULT now(),
    priority smallint NOT NULL DEFAULT 1,
    args jsonb NOT NULL,
    attempted_by text[],
    errors jsonb[],
    kind text NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}',
    queue text NOT NULL DEFAULT 'default',
    tags varchar(255)[] NOT NULL DEFAULT '{}',
    unique_key bytea,
    unique_states bit(8),
    CONSTRAINT river_job_finalized_at_state CHECK (
        (finalized_at IS NULL AND state NOT IN ('cancelled', 'completed', 'discarded')) OR
        (finalized_at IS NOT NULL AND state IN ('cancelled', 'completed', 'discarded'))
    ),
    CONSTRAINT river_job_max_attempts_positive CHECK (max_attempts > 0),
    CONSTRAINT river_job_priority_range CHECK (priority BETWEEN 1 AND 4),
    CONSTRAINT river_job_queue_length CHECK (char_length(queue) > 0 AND char_length(queue) < 128),
    CONSTRAINT river_job_kind_length CHECK (char_length(kind) > 0 AND char_length(kind) < 128)
);

CREATE INDEX river_job_kind ON river_job USING btree(kind);
CREATE INDEX river_job_state_and_finalized_at_index ON river_job USING btree(state, finalized_at) WHERE finalized_at IS NOT NULL;
CREATE INDEX river_job_prioritized_fetching_index ON river_job USING btree(state, queue, priority, scheduled_at, id);
CREATE INDEX river_job_args_index ON river_job USING GIN(args);
CREATE INDEX river_job_metadata_index ON river_job USING GIN(metadata);

-- River uses this immutable helper for unique-job state masks.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION river_job_state_in_bitmask(bitmask bit(8), state river_job_state)
RETURNS boolean
LANGUAGE SQL
IMMUTABLE
AS $$
    SELECT CASE state
        WHEN 'available' THEN get_bit(bitmask, 7)
        WHEN 'cancelled' THEN get_bit(bitmask, 6)
        WHEN 'completed' THEN get_bit(bitmask, 5)
        WHEN 'discarded' THEN get_bit(bitmask, 4)
        WHEN 'pending' THEN get_bit(bitmask, 3)
        WHEN 'retryable' THEN get_bit(bitmask, 2)
        WHEN 'running' THEN get_bit(bitmask, 1)
        WHEN 'scheduled' THEN get_bit(bitmask, 0)
        ELSE 0
    END = 1;
$$;
-- +goose StatementEnd

CREATE UNIQUE INDEX river_job_unique_idx ON river_job (unique_key)
WHERE unique_key IS NOT NULL
  AND unique_states IS NOT NULL
  AND river_job_state_in_bitmask(unique_states, state);

CREATE TABLE river_queue (
    name text PRIMARY KEY NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    metadata jsonb NOT NULL DEFAULT '{}',
    paused_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNLOGGED TABLE river_leader (
    elected_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    leader_id text NOT NULL,
    name text PRIMARY KEY DEFAULT 'default',
    CONSTRAINT river_leader_name CHECK (name = 'default'),
    CONSTRAINT river_leader_id_length CHECK (char_length(leader_id) > 0 AND char_length(leader_id) < 128)
);

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
