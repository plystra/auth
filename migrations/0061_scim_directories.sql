-- +goose Up

CREATE TABLE IF NOT EXISTS directories (
    id text PRIMARY KEY CHECK (id LIKE 'dir_%'),
    space_id text NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
    token_prefix text NOT NULL UNIQUE,
    token_hash bytea NOT NULL UNIQUE,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (space_id, name)
);
CREATE INDEX IF NOT EXISTS directories_space_idx ON directories(space_id, status, created_at);

CREATE TABLE IF NOT EXISTS directory_users (
    id text PRIMARY KEY CHECK (id LIKE 'dusr_%'),
    directory_id text NOT NULL REFERENCES directories(id) ON DELETE CASCADE,
    external_id text NOT NULL CHECK (length(external_id) BETWEEN 1 AND 512),
    user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    member_id text NOT NULL REFERENCES members(id) ON DELETE CASCADE,
    user_name text NOT NULL,
    display_name text NOT NULL DEFAULT '',
    active boolean NOT NULL DEFAULT true,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (directory_id, external_id),
    UNIQUE (directory_id, user_id),
    UNIQUE (directory_id, member_id)
);
CREATE INDEX IF NOT EXISTS directory_users_directory_idx ON directory_users(directory_id, active, created_at);

CREATE TABLE IF NOT EXISTS directory_groups (
    id text PRIMARY KEY CHECK (id LIKE 'dgrp_%'),
    directory_id text NOT NULL REFERENCES directories(id) ON DELETE CASCADE,
    external_id text NOT NULL CHECK (length(external_id) BETWEEN 1 AND 512),
    group_id text NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    display_name text NOT NULL,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (directory_id, external_id),
    UNIQUE (directory_id, group_id)
);
CREATE INDEX IF NOT EXISTS directory_groups_directory_idx ON directory_groups(directory_id, created_at);

CREATE TABLE IF NOT EXISTS directory_group_members (
    directory_group_id text NOT NULL REFERENCES directory_groups(id) ON DELETE CASCADE,
    member_id text NOT NULL REFERENCES members(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (directory_group_id, member_id)
);

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
