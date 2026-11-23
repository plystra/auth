-- +goose Up

CREATE TABLE signing_keys (
    kid text PRIMARY KEY CHECK (kid ~ '^[0-9a-f]{16}$'),
    issuer text NOT NULL CHECK (issuer <> ''),
    private_key_ciphertext bytea NOT NULL CHECK (octet_length(private_key_ciphertext) > 28),
    status text NOT NULL CHECK (status IN ('next', 'active', 'retiring'))
);

CREATE UNIQUE INDEX signing_keys_current_status_idx
    ON signing_keys (status) WHERE status IN ('next', 'active');

REVOKE UPDATE, DELETE ON TABLE signing_keys FROM plystra_auth_app;
ALTER TABLE signing_keys ENABLE ROW LEVEL SECURITY;
CREATE POLICY signing_keys_read ON signing_keys
    FOR SELECT TO plystra_auth_app USING (true);
CREATE POLICY signing_keys_bootstrap ON signing_keys
    FOR INSERT TO plystra_auth_app WITH CHECK (status = 'active');
