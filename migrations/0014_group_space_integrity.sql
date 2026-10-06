-- +goose Up

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM group_members gm
        JOIN groups g ON g.id = gm.group_id
        JOIN members m ON m.id = gm.member_id
        WHERE g.space_id <> m.space_id
    ) THEN
        RAISE EXCEPTION 'group_members contains cross-Space memberships; repair them before migrating';
    END IF;
    IF EXISTS (
        SELECT 1 FROM groups child
        JOIN groups parent ON parent.id = child.parent_id
        WHERE child.space_id <> parent.space_id
    ) THEN
        RAISE EXCEPTION 'groups contains cross-Space parent links; repair them before migrating';
    END IF;
END $$;
-- +goose StatementEnd

ALTER TABLE groups ADD CONSTRAINT groups_id_space_unique UNIQUE (id, space_id);
ALTER TABLE members ADD CONSTRAINT members_id_space_unique UNIQUE (id, space_id);

ALTER TABLE group_members ADD COLUMN space_id text;
UPDATE group_members gm SET space_id = g.space_id FROM groups g WHERE gm.group_id = g.id;
ALTER TABLE group_members ALTER COLUMN space_id SET NOT NULL;

ALTER TABLE group_members ADD CONSTRAINT group_members_group_space_fk
    FOREIGN KEY (group_id, space_id) REFERENCES groups (id, space_id) ON DELETE CASCADE;
ALTER TABLE group_members ADD CONSTRAINT group_members_member_space_fk
    FOREIGN KEY (member_id, space_id) REFERENCES members (id, space_id) ON DELETE CASCADE;
ALTER TABLE groups ADD CONSTRAINT groups_parent_space_fk
    FOREIGN KEY (parent_id, space_id) REFERENCES groups (id, space_id);

-- +goose StatementBegin
CREATE FUNCTION set_group_member_space() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    group_space text;
BEGIN
    SELECT g.space_id INTO group_space FROM groups g WHERE g.id = NEW.group_id;
    IF group_space IS NULL THEN
        RAISE EXCEPTION 'group % does not exist', NEW.group_id USING ERRCODE = '23503';
    END IF;
    IF NEW.space_id IS NOT NULL AND NEW.space_id <> group_space THEN
        RAISE EXCEPTION 'group membership Space does not match its group' USING ERRCODE = '23514';
    END IF;
    NEW.space_id := group_space;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER group_members_set_space
    BEFORE INSERT OR UPDATE OF group_id, space_id ON group_members
    FOR EACH ROW EXECUTE FUNCTION set_group_member_space();

-- +goose Down
-- Forward-only migration: use a compensating migration if rollback is required.
