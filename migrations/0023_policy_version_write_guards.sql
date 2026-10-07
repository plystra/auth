-- +goose Up

-- Policy-version changes must also cover direct database writers. The service
-- still performs explicit bumps for multi-step writes that touch role and
-- assignment tables, while these guards cover policy rows that can otherwise
-- leave a cached decision valid after the underlying policy changed.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION bump_space_policy_for_group_status()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE spaces SET policy_version = policy_version + 1 WHERE id = COALESCE(NEW.space_id, OLD.space_id);
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS groups_auth_policy_status ON groups;
CREATE TRIGGER groups_auth_policy_status
AFTER UPDATE OF status ON groups
FOR EACH ROW
WHEN (OLD.status IS DISTINCT FROM NEW.status)
EXECUTE FUNCTION bump_space_policy_for_group_status();

-- Human member status changes affect every decision in the member's Space.
-- Agent state is intentionally versioned on the member row itself, so it does
-- not invalidate unrelated Space decisions.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION bump_space_policy_for_human_member_status()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF COALESCE(NEW.type, OLD.type) <> 'agent' THEN
        UPDATE spaces SET policy_version = policy_version + 1 WHERE id = COALESCE(NEW.space_id, OLD.space_id);
    END IF;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS members_auth_policy_status ON members;
CREATE TRIGGER members_auth_policy_status
AFTER UPDATE OF status ON members
FOR EACH ROW
WHEN (OLD.status IS DISTINCT FROM NEW.status)
EXECUTE FUNCTION bump_space_policy_for_human_member_status();

-- Grants are policy rows. Service grant writes rely on this trigger so that
-- direct writers and other service instances use the same version path.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION bump_space_policy_for_grant_revocation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE spaces SET policy_version = policy_version + 1 WHERE id = COALESCE(NEW.space_id, OLD.space_id);
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS grants_auth_policy_revocation ON authorization_grants;
DROP TRIGGER IF EXISTS grants_auth_policy_mutation ON authorization_grants;
CREATE TRIGGER grants_auth_policy_mutation
AFTER INSERT OR UPDATE OR DELETE ON authorization_grants
FOR EACH ROW
EXECUTE FUNCTION bump_space_policy_for_grant_revocation();

-- Group membership changes alter the resource facts used by scoped grants.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION bump_space_policy_for_group_membership()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    affected_group text := COALESCE(NEW.group_id, OLD.group_id);
BEGIN
    UPDATE spaces
    SET policy_version = policy_version + 1
    WHERE id = (SELECT space_id FROM groups WHERE id = affected_group);
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS group_members_auth_policy_mutation ON group_members;
CREATE TRIGGER group_members_auth_policy_mutation
AFTER INSERT OR UPDATE OR DELETE ON group_members
FOR EACH ROW
EXECUTE FUNCTION bump_space_policy_for_group_membership();

-- Envelope rows are policy facts and must invalidate the owning Space.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION bump_space_policy_for_envelope()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    new_row jsonb := to_jsonb(NEW);
    old_row jsonb := to_jsonb(OLD);
    affected_space text := COALESCE(new_row ->> 'space_id', old_row ->> 'space_id');
    affected_group text := COALESCE(new_row ->> 'group_id', old_row ->> 'group_id');
BEGIN
    IF affected_space IS NULL AND affected_group IS NOT NULL THEN
        SELECT space_id INTO affected_space FROM groups WHERE id = affected_group;
    END IF;
    UPDATE spaces SET policy_version = policy_version + 1 WHERE id = affected_space;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS space_envelopes_auth_policy_mutation ON space_envelopes;
CREATE TRIGGER space_envelopes_auth_policy_mutation
AFTER INSERT OR UPDATE OR DELETE ON space_envelopes
FOR EACH ROW
EXECUTE FUNCTION bump_space_policy_for_envelope();

DROP TRIGGER IF EXISTS space_envelope_entries_auth_policy_mutation ON space_envelope_entries;
CREATE TRIGGER space_envelope_entries_auth_policy_mutation
AFTER INSERT OR UPDATE OR DELETE ON space_envelope_entries
FOR EACH ROW
EXECUTE FUNCTION bump_space_policy_for_envelope();

DROP TRIGGER IF EXISTS group_envelopes_auth_policy_mutation ON group_envelopes;
CREATE TRIGGER group_envelopes_auth_policy_mutation
AFTER INSERT OR UPDATE OR DELETE ON group_envelopes
FOR EACH ROW
EXECUTE FUNCTION bump_space_policy_for_envelope();

DROP TRIGGER IF EXISTS group_envelope_entries_auth_policy_mutation ON group_envelope_entries;
CREATE TRIGGER group_envelope_entries_auth_policy_mutation
AFTER INSERT OR UPDATE OR DELETE ON group_envelope_entries
FOR EACH ROW
EXECUTE FUNCTION bump_space_policy_for_envelope();

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
