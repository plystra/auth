-- +goose Up

-- Agent groups are part of the delegation tree and are not ordinary groups.
-- Keep the invariant in PostgreSQL as well as in the service so direct writers
-- cannot create a group layout the authorization evaluator does not understand.
-- Human and application owners get a top-level Agent group; an Agent owner
-- gets a child group directly below its own home group. Standard groups may
-- never be created below an Agent group.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION enforce_agent_group_structure() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    owner_type text;
    owner_home_group text;
    parent_kind text;
    parent_space text;
BEGIN
    IF TG_OP = 'UPDATE' AND OLD.kind = 'agents' AND (
        NEW.kind IS DISTINCT FROM OLD.kind
        OR NEW.owner_member_id IS DISTINCT FROM OLD.owner_member_id
        OR NEW.parent_id IS DISTINCT FROM OLD.parent_id
    ) THEN
        RAISE EXCEPTION 'Agent groups cannot be moved or transferred' USING ERRCODE = '42501';
    END IF;

    IF NEW.kind = 'agents' THEN
        IF NEW.owner_member_id IS NULL THEN
            RAISE EXCEPTION 'Agent groups require an owner member' USING ERRCODE = '23514';
        END IF;

        SELECT m.type, m.home_group_id
        INTO owner_type, owner_home_group
        FROM members m
        WHERE m.id = NEW.owner_member_id;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'Agent group owner does not exist' USING ERRCODE = '23503';
        END IF;

        IF owner_type IN ('human', 'application') THEN
            IF NEW.parent_id IS NOT NULL THEN
                RAISE EXCEPTION 'Human and application Agent groups must be top-level' USING ERRCODE = '23514';
            END IF;
        ELSIF owner_type = 'agent' THEN
            IF owner_home_group IS NULL OR NEW.parent_id IS DISTINCT FROM owner_home_group THEN
                RAISE EXCEPTION 'An Agent group must be directly below its owner home group' USING ERRCODE = '23514';
            END IF;
            SELECT g.kind, g.space_id
            INTO parent_kind, parent_space
            FROM groups g
            WHERE g.id = NEW.parent_id;
            IF NOT FOUND OR parent_kind <> 'agents' OR parent_space <> NEW.space_id THEN
                RAISE EXCEPTION 'An Agent group parent must be an Agent group in the same Space' USING ERRCODE = '23514';
            END IF;
        ELSE
            RAISE EXCEPTION 'Agent group owner has an invalid member type' USING ERRCODE = '23514';
        END IF;
    ELSE
        IF NEW.owner_member_id IS NOT NULL THEN
            RAISE EXCEPTION 'Standard groups cannot have an Agent owner' USING ERRCODE = '23514';
        END IF;
        IF NEW.parent_id IS NOT NULL THEN
            SELECT g.kind INTO parent_kind FROM groups g WHERE g.id = NEW.parent_id;
            IF parent_kind = 'agents' THEN
                RAISE EXCEPTION 'Standard groups cannot be children of Agent groups' USING ERRCODE = '42501';
            END IF;
        END IF;
    END IF;

    RETURN NEW;
END;
$$;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS groups_agent_structure_guard ON groups;
CREATE TRIGGER groups_agent_structure_guard
    BEFORE INSERT OR UPDATE OF kind, owner_member_id, parent_id ON groups
    FOR EACH ROW EXECUTE FUNCTION enforce_agent_group_structure();

-- +goose Down
-- Forward-only migration: replace this migration with a compensating migration.
