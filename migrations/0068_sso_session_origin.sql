-- +goose Up

ALTER TABLE sessions ADD COLUMN sso_member_id text REFERENCES members(id);

-- Old enterprise sessions can already have switched away from their login member.
UPDATE sessions SET revoked_at = now()
WHERE revoked_at IS NULL AND auth_methods && ARRAY['oidc', 'saml']::text[];

UPDATE refresh_tokens SET revoked_at = now()
WHERE revoked_at IS NULL AND session_id IN (
    SELECT id FROM sessions WHERE auth_methods && ARRAY['oidc', 'saml']::text[]
);

ALTER TABLE sessions ADD CONSTRAINT sessions_sso_member_context CHECK (
    CASE WHEN auth_methods && ARRAY['oidc', 'saml']::text[]
        THEN sso_member_id IS NOT NULL OR revoked_at IS NOT NULL
        ELSE sso_member_id IS NULL
    END
);

CREATE INDEX sessions_sso_binding_idx ON sessions(user_id, sso_member_id)
WHERE sso_member_id IS NOT NULL;
