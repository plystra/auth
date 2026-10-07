-- +goose Up

-- Policy versions are bumped in the same transaction as authorization writes.
-- PostgreSQL delivers this notification only after that transaction commits,
-- so other nodes never invalidate from an uncommitted policy change.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION notify_auth_policy_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.policy_version IS DISTINCT FROM NEW.policy_version THEN
        PERFORM pg_notify('auth_policy', NEW.id);
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER spaces_auth_policy_notify
AFTER UPDATE OF policy_version ON spaces
FOR EACH ROW
EXECUTE FUNCTION notify_auth_policy_change();

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
