-- +goose Up

-- Publishers opt their clients into human OIDC sign-in independently of
-- business permissions. Existing clients retain their original behavior.
ALTER TABLE applications ADD COLUMN human_oidc_enabled boolean NOT NULL DEFAULT false;
