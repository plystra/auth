-- +goose Up

-- A directory trusts an explicitly selected connection and stable claim,
-- never an email coincidence. Enforce tenant ownership in the database too.
ALTER TABLE sso_connections ADD CONSTRAINT sso_connections_id_space_unique UNIQUE (id, space_id);
ALTER TABLE directories ADD COLUMN sso_connection_id text;
ALTER TABLE directories ADD COLUMN sso_identity_claim text;
ALTER TABLE directories ADD CONSTRAINT directories_sso_connection_space_fk
    FOREIGN KEY (sso_connection_id, space_id) REFERENCES sso_connections(id, space_id);
ALTER TABLE directories ADD CONSTRAINT directories_sso_identity_pair CHECK (
    (sso_connection_id IS NULL AND sso_identity_claim IS NULL)
    OR (sso_connection_id IS NOT NULL AND sso_identity_claim IS NOT NULL
        AND length(sso_identity_claim) BETWEEN 1 AND 512)
);
CREATE UNIQUE INDEX directories_active_sso_connection_unique
    ON directories(sso_connection_id) WHERE status = 'active' AND sso_connection_id IS NOT NULL;

-- Keep directory provenance after unlinking or offboarding so a later SSO
-- callback cannot silently recreate a revoked binding through the JIT path.
ALTER TABLE external_identities ADD COLUMN directory_user_id text REFERENCES directory_users(id);
CREATE INDEX external_identities_directory_user_idx ON external_identities(directory_user_id)
    WHERE directory_user_id IS NOT NULL;

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
