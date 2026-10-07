-- name: GetAuthorizationCatalogVersion :one
SELECT version
FROM authorization_policy_state
WHERE id = TRUE;
