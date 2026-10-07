-- +goose Up

-- Tombstoned members and Agent groups retain identity references for audit and
-- self scope resolution, but they must never retain live authority. Keep this
-- invariant in PostgreSQL so direct writers and concurrent service instances
-- cannot re-grant a removed principal.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION reject_tombstone_authorization_grant()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.revoked_at IS NULL
       AND NEW.grantee_member_id IS NOT NULL
       AND EXISTS (
           SELECT 1 FROM members
           WHERE id = NEW.grantee_member_id AND status = 'removed'
       ) THEN
        RAISE EXCEPTION 'removed members cannot hold authorization grants' USING ERRCODE = '42501';
    END IF;
    IF NEW.revoked_at IS NULL
       AND NEW.grantee_group_id IS NOT NULL
       AND EXISTS (
           SELECT 1 FROM groups
           WHERE id = NEW.grantee_group_id AND status = 'removed'
       ) THEN
        RAISE EXCEPTION 'removed groups cannot hold authorization grants' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS authorization_grants_tombstone_guard ON authorization_grants;
CREATE TRIGGER authorization_grants_tombstone_guard
    BEFORE INSERT OR UPDATE ON authorization_grants
    FOR EACH ROW EXECUTE FUNCTION reject_tombstone_authorization_grant();

-- Revocation must also happen for direct database status changes. The row is
-- retained for audit, but no active grant may survive the tombstone transition.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION revoke_tombstone_member_grants()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE authorization_grants
    SET revoked_at = now()
    WHERE grantee_member_id = NEW.id
      AND revoked_at IS NULL;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS members_tombstone_grants ON members;
CREATE TRIGGER members_tombstone_grants
    AFTER UPDATE OF status ON members
    FOR EACH ROW
    WHEN (OLD.status IS DISTINCT FROM NEW.status AND NEW.status = 'removed')
    EXECUTE FUNCTION revoke_tombstone_member_grants();

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION revoke_tombstone_group_grants()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE authorization_grants
    SET revoked_at = now()
    WHERE grantee_group_id = NEW.id
      AND revoked_at IS NULL;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS groups_tombstone_grants ON groups;
CREATE TRIGGER groups_tombstone_grants
    AFTER UPDATE OF status ON groups
    FOR EACH ROW
    WHEN (OLD.status IS DISTINCT FROM NEW.status AND NEW.status = 'removed')
    EXECUTE FUNCTION revoke_tombstone_group_grants();

UPDATE authorization_grants ag
SET revoked_at = now()
FROM members m
WHERE ag.grantee_member_id = m.id
  AND m.status = 'removed'
  AND ag.revoked_at IS NULL;

UPDATE authorization_grants ag
SET revoked_at = now()
FROM groups g
WHERE ag.grantee_group_id = g.id
  AND g.status = 'removed'
  AND ag.revoked_at IS NULL;

-- +goose Down
-- Forward-only migrations: replace this migration with a compensating migration.
