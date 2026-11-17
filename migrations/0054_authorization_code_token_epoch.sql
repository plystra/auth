-- +goose Up

-- Authorization codes cannot restore credentials revoked by Agent suspension.
-- Bind new codes to the existing Agent token epoch. Legacy codes deliberately
-- remain unbound and fail closed: their issue-time epoch cannot be recovered.
ALTER TABLE authorization_codes
    ADD COLUMN member_token_epoch bigint CHECK (member_token_epoch > 0);

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
