-- +goose Up

-- Agent-local changes invalidate the Agent and delegated descendants through
-- member versions. They must not invalidate unrelated Space authority. Keep
-- the same rules for direct database writers and application transactions.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION bump_space_policy_for_group_status()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.kind = 'agents' THEN
        UPDATE members SET version = version + 1
        WHERE home_group_id = NEW.id AND type = 'agent';
    ELSE
        UPDATE spaces SET policy_version = policy_version + 1 WHERE id = NEW.space_id;
    END IF;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION bump_space_policy_for_grant_revocation()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    affected record;
BEGIN
    FOR affected IN
        SELECT DISTINCT v.space_id, v.member_id, v.group_id
        FROM (VALUES (OLD.space_id, OLD.grantee_member_id, OLD.grantee_group_id),
                     (NEW.space_id, NEW.grantee_member_id, NEW.grantee_group_id))
             AS v(space_id, member_id, group_id)
        WHERE v.space_id IS NOT NULL
    LOOP
        IF EXISTS (SELECT 1 FROM members WHERE id = affected.member_id AND type = 'agent') THEN
            UPDATE members SET version = version + 1 WHERE id = affected.member_id;
        ELSIF EXISTS (SELECT 1 FROM groups WHERE id = affected.group_id AND kind = 'agents') THEN
            UPDATE members SET version = version + 1
            WHERE home_group_id = affected.group_id AND type = 'agent';
        ELSE
            UPDATE spaces SET policy_version = policy_version + 1 WHERE id = affected.space_id;
        END IF;
    END LOOP;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION bump_space_policy_for_group_membership()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    affected record;
BEGIN
    FOR affected IN
        SELECT DISTINCT v.group_id, v.member_id
        FROM (VALUES (OLD.group_id, OLD.member_id), (NEW.group_id, NEW.member_id))
             AS v(group_id, member_id)
        WHERE v.group_id IS NOT NULL
    LOOP
        IF EXISTS (SELECT 1 FROM members WHERE id = affected.member_id AND type = 'agent') THEN
            UPDATE members SET version = version + 1 WHERE id = affected.member_id;
        ELSE
            UPDATE spaces SET policy_version = policy_version + 1
            WHERE id = (SELECT space_id FROM groups WHERE id = affected.group_id);
        END IF;
    END LOOP;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

-- Credential security state participates in Agent cache versions; updating a
-- key's usage timestamp alone does not change its authority or validity.
-- +goose StatementBegin
CREATE FUNCTION bump_agent_policy_for_credential()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND ROW(OLD.member_id, OLD.kind, OLD.prefix, OLD.secret_hash, OLD.family_id, OLD.expires_at, OLD.revoked_at)
           IS NOT DISTINCT FROM
           ROW(NEW.member_id, NEW.kind, NEW.prefix, NEW.secret_hash, NEW.family_id, NEW.expires_at, NEW.revoked_at)
       AND (NEW.kind <> 'oauth_refresh' OR OLD.last_used_at IS NOT DISTINCT FROM NEW.last_used_at) THEN
        RETURN NULL;
    END IF;
    UPDATE members SET version = version + 1
    WHERE type = 'agent' AND id IN (OLD.member_id, NEW.member_id);
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER agent_credentials_auth_policy_mutation
AFTER INSERT OR UPDATE OR DELETE ON agent_credentials
FOR EACH ROW EXECUTE FUNCTION bump_agent_policy_for_credential();

-- +goose Down
-- Forward-only migration: use a compensating migration for any later change.
