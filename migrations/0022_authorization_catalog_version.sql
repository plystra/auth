-- +goose Up

-- Permission-directory changes are global policy changes. They use a separate
-- monotonic version because no individual Space version can represent them.
CREATE TABLE IF NOT EXISTS authorization_policy_state (
    id boolean PRIMARY KEY DEFAULT TRUE CHECK (id),
    version bigint NOT NULL DEFAULT 1
);

INSERT INTO authorization_policy_state (id, version)
VALUES (TRUE, 1)
ON CONFLICT (id) DO NOTHING;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION bump_authorization_catalog_version()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    next_version bigint;
BEGIN
    UPDATE authorization_policy_state
    SET version = version + 1
    WHERE id = TRUE
    RETURNING version INTO next_version;
    PERFORM pg_notify('auth_policy', 'catalog:' || next_version::text);
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS permissions_auth_policy_catalog ON permissions;
CREATE TRIGGER permissions_auth_policy_catalog
AFTER INSERT OR UPDATE OR DELETE ON permissions
FOR EACH STATEMENT
EXECUTE FUNCTION bump_authorization_catalog_version();

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
