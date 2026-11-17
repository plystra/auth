-- +goose Up

-- A resumed Agent must not revalidate access tokens issued before suspension.
-- Keep this separate from authority versions: grant changes must still be
-- evaluated using the token's scope and the current authorization facts.
ALTER TABLE members ADD COLUMN token_epoch bigint NOT NULL DEFAULT 1 CHECK (token_epoch > 0);

-- +goose StatementBegin
CREATE FUNCTION invalidate_agent_tokens_on_deactivation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.type = 'agent' AND OLD.status = 'active' AND NEW.status <> 'active' THEN
        NEW.token_epoch := OLD.token_epoch + 1;
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER members_agent_token_deactivation
BEFORE UPDATE OF status ON members
FOR EACH ROW EXECUTE FUNCTION invalidate_agent_tokens_on_deactivation();

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
