-- name: EnsureDefaultSpace :exec
INSERT INTO spaces (id, name, slug)
VALUES ('spc_01h00000000000000000000000', 'Default Space', 'default')
ON CONFLICT (id) DO NOTHING;

-- name: EnsureDefaultApplication :exec
INSERT INTO applications (id, space_id, name, client_id, redirect_uris, allowed_scopes)
VALUES (
    'app_01h00000000000000000000000',
    'spc_01h00000000000000000000000',
    'Default Application',
    'default',
    '[]'::jsonb,
    '["auth.authz:check", "auth.tokens:introspect"]'::jsonb
)
ON CONFLICT (id) DO UPDATE
SET allowed_scopes = EXCLUDED.allowed_scopes
WHERE applications.allowed_scopes = '[]'::jsonb;

-- name: CountAPIKeysForApplication :one
SELECT count(*)::bigint
FROM api_keys
WHERE application_id = sqlc.arg(application_id);
