-- name: InitializeSigningKey :exec
INSERT INTO signing_keys (kid, issuer, private_key_ciphertext, status)
SELECT sqlc.arg(kid), sqlc.arg(issuer), sqlc.arg(private_key_ciphertext), 'active'
WHERE NOT EXISTS (SELECT 1 FROM signing_keys)
ON CONFLICT DO NOTHING;

-- name: ListSigningKeys :many
SELECT kid, issuer, private_key_ciphertext, status
FROM signing_keys
ORDER BY kid;
