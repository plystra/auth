-- +goose Up

ALTER TABLE sign_in_attempts ADD COLUMN target_space_id text;

-- Outstanding attempts did not preserve the requested Space.
UPDATE sign_in_attempts SET consumed_at = now()
WHERE consumed_at IS NULL AND expires_at > now();
