-- Dev bootstrap (runs once on first container start).
-- Idempotent by design: packaging/install.ps1 -ProvisionDatabase and
-- packaging/drill.ps1 re-run this on a clean Windows VM, so every statement
-- is guarded. Docker's initdb runs it once; re-running must be a no-op.
--
-- Migration role owns the schema; the app role has no BYPASSRLS (schema.sql header).
-- Worker role is the platform job processor: BYPASSRLS so one worker fleet can
-- claim jobs across tenants (schema owner would otherwise be the only bypass).

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_app') THEN
        CREATE ROLE sentinel_app LOGIN PASSWORD 'sentinel_app'
            NOSUPERUSER NOBYPASSRLS NOCREATEDB;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_migrator') THEN
        CREATE ROLE sentinel_migrator LOGIN PASSWORD 'sentinel_migrator'
            NOSUPERUSER NOBYPASSRLS NOCREATEDB;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_worker') THEN
        CREATE ROLE sentinel_worker LOGIN PASSWORD 'sentinel_worker'
            NOSUPERUSER BYPASSRLS NOCREATEDB;
    END IF;
END
$$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_database WHERE datname = 'sentinel') THEN
        GRANT CREATE ON DATABASE sentinel TO sentinel_migrator;
        GRANT CONNECT ON DATABASE sentinel TO sentinel_app;
        GRANT CONNECT ON DATABASE sentinel TO sentinel_worker;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'public') THEN
        -- PG15+ revokes CREATE on schema public from PUBLIC; the migrator owns DDL.
        GRANT CREATE, USAGE ON SCHEMA public TO sentinel_migrator;
        GRANT USAGE ON SCHEMA public TO sentinel_app, sentinel_worker;
    END IF;
END
$$;
