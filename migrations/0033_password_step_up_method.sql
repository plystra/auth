-- +goose Up

ALTER TABLE sessions
    ADD COLUMN step_up_method text
    CONSTRAINT sessions_step_up_method_check CHECK (step_up_method IN ('totp', 'password'));

-- +goose Down
-- Forward-only migrations: add a compensating migration if removal is required.
