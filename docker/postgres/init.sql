DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'plystra_auth_owner') THEN
        CREATE ROLE plystra_auth_owner LOGIN PASSWORD 'dev-owner-password';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'plystra_auth_app') THEN
        CREATE ROLE plystra_auth_app LOGIN PASSWORD 'dev-app-password';
    END IF;
END
$$;

GRANT CONNECT ON DATABASE plystra_auth TO plystra_auth_owner, plystra_auth_app;
GRANT USAGE, CREATE ON SCHEMA public TO plystra_auth_owner;
