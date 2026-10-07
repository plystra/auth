-- +goose Up

-- Operators and member bindings are mutually exclusive identities. Check the
-- existing data before installing the guards so a partially migrated database
-- fails closed with an actionable error.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM operators o
        JOIN user_members um ON um.user_id = o.user_id
        WHERE um.status = 'active'
          AND um.revoked_at IS NULL
          AND (um.expires_at IS NULL OR um.expires_at > now())
    ) THEN
        RAISE EXCEPTION 'operators and active member bindings are mutually exclusive';
    END IF;
END
$$;
-- +goose StatementEnd

-- A member binding cannot be created or reactivated for an operator identity.
-- The check remains in the database so direct writers cannot bypass the
-- service-level validation.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION reject_operator_member_binding() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status = 'active'
       AND NEW.revoked_at IS NULL
       AND (NEW.expires_at IS NULL OR NEW.expires_at > now())
       AND EXISTS (SELECT 1 FROM operators WHERE user_id = NEW.user_id)
    THEN
        RAISE EXCEPTION 'operator identities cannot have active member bindings' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS user_members_operator_exclusion ON user_members;
CREATE TRIGGER user_members_operator_exclusion
BEFORE INSERT OR UPDATE OF user_id, status, expires_at, revoked_at ON user_members
FOR EACH ROW EXECUTE FUNCTION reject_operator_member_binding();

-- An operator cannot be created for a user who already has an active member
-- binding. This protects direct SQL writers as well as the operations plane.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION reject_member_operator_identity() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM user_members
        WHERE user_id = NEW.user_id
          AND status = 'active'
          AND revoked_at IS NULL
          AND (expires_at IS NULL OR expires_at > now())
    ) THEN
        RAISE EXCEPTION 'active member identities cannot become operators' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS operators_member_exclusion ON operators;
CREATE TRIGGER operators_member_exclusion
BEFORE INSERT OR UPDATE OF user_id ON operators
FOR EACH ROW EXECUTE FUNCTION reject_member_operator_identity();

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
