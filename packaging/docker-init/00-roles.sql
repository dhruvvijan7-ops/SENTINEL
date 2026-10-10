-- Dev bootstrap (runs once on first container start).
-- Migration role owns the schema; the app role has no BYPASSRLS (schema.sql header).
-- Worker role is the platform job processor: BYPASSRLS so one worker fleet can
-- claim jobs across tenants (schema owner would otherwise be the only bypass).
CREATE ROLE sentinel_app LOGIN PASSWORD 'sentinel_app' NOSUPERUSER NOBYPASSRLS NOCREATEDB;
CREATE ROLE sentinel_migrator LOGIN PASSWORD 'sentinel_migrator' NOSUPERUSER NOBYPASSRLS NOCREATEDB;
CREATE ROLE sentinel_worker LOGIN PASSWORD 'sentinel_worker' NOSUPERUSER BYPASSRLS NOCREATEDB;
GRANT CREATE ON DATABASE sentinel TO sentinel_migrator;
GRANT CONNECT ON DATABASE sentinel TO sentinel_app;
GRANT CONNECT ON DATABASE sentinel TO sentinel_worker;
-- PG15+ revokes CREATE on schema public from PUBLIC; the migrator owns DDL.
GRANT CREATE, USAGE ON SCHEMA public TO sentinel_migrator;
GRANT USAGE ON SCHEMA public TO sentinel_app, sentinel_worker;
