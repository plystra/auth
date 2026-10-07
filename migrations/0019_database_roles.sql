-- +goose Up

-- The migration URL must use the owner role. Deployment provisioning creates
-- both canonical roles; this migration only grants the application role the
-- least privilege needed by the service.
-- +goose StatementBegin
DO $$
BEGIN
    IF current_user <> 'plystra_auth_owner' THEN
        RAISE EXCEPTION 'database migrations must run as plystra_auth_owner (current role: %)', current_user;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'plystra_auth_app') THEN
        RAISE EXCEPTION 'required role plystra_auth_app does not exist';
    END IF;
END
$$;
-- +goose StatementEnd

GRANT USAGE ON SCHEMA public TO plystra_auth_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO plystra_auth_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO plystra_auth_app;
GRANT SELECT, INSERT ON TABLE audit_logs TO plystra_auth_app;
REVOKE UPDATE, DELETE ON TABLE audit_logs FROM plystra_auth_app;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO plystra_auth_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO plystra_auth_app;

-- +goose Down
-- Forward-only migrations: restore from a PostgreSQL backup or add a compensating migration.
