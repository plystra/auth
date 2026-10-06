-- +goose Up

-- An absent policy inherits its parent. A present policy lists the complete
-- local ceiling; omitted permissions are excluded at this node.
CREATE TABLE space_envelopes (
    space_id text PRIMARY KEY REFERENCES spaces(id)
);

CREATE TABLE space_envelope_entries (
    space_id text NOT NULL REFERENCES space_envelopes(space_id),
    permission_id text NOT NULL REFERENCES permissions(id),
    mode text NOT NULL CHECK (mode IN ('use', 'assign', 'delegate')),
    PRIMARY KEY (space_id, permission_id)
);

CREATE TABLE group_envelopes (
    group_id text PRIMARY KEY REFERENCES groups(id)
);

CREATE TABLE group_envelope_entries (
    group_id text NOT NULL REFERENCES group_envelopes(group_id),
    permission_id text NOT NULL REFERENCES permissions(id),
    mode text NOT NULL CHECK (mode IN ('use', 'assign', 'delegate')),
    PRIMARY KEY (group_id, permission_id)
);

-- +goose Down
-- Forward-only migration: replace this migration with a compensating migration.
