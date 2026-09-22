-- Cluster-level role bootstrap (ARCHITECTURE.md §24). Run once per cluster by
-- the bootstrap superuser with psql, before migrations:
--
--   psql -v ON_ERROR_STOP=1 -v dbname=aitl \
--        -v ingest_writer_password=... -v intel_svc_password=... \
--        -v scenario_gen_password=... -v agent_svc_password=... \
--        -v gateway_svc_password=... -v eval_svc_password=... \
--        -f init-roles.sql
--
-- Passwords are supplied as psql variables from per-deployment secret files
-- (deploy/secrets/generate.sh); none is stored in this repository.
--
-- Roles:
--   aitl_owner  NOLOGIN. Owns the database and every schema object. Migrations
--               run as the bootstrap superuser with `SET ROLE aitl_owner`, so the
--               owner never has credentials and no runtime service can act as it.
--   runtime     LOGIN, no attributes, no ownership; privileges are granted per
--               object by migration 0012 only.
-- Idempotent: safe to re-run (roles are created if missing, then normalized).

\set ON_ERROR_STOP on

SELECT 'CREATE ROLE aitl_owner NOLOGIN'
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aitl_owner') \gexec

ALTER ROLE aitl_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    NOINHERIT;

SELECT format('CREATE ROLE %I LOGIN', role_name)
FROM unnest(ARRAY[
    'ingest_writer', 'intel_svc', 'scenario_gen', 'agent_svc', 'gateway_svc', 'eval_svc'
]) AS role_name
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) \gexec

ALTER ROLE ingest_writer LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    NOINHERIT PASSWORD :'ingest_writer_password';
ALTER ROLE intel_svc LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    NOINHERIT PASSWORD :'intel_svc_password';
ALTER ROLE scenario_gen LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    NOINHERIT PASSWORD :'scenario_gen_password';
ALTER ROLE agent_svc LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    NOINHERIT PASSWORD :'agent_svc_password';
ALTER ROLE gateway_svc LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    NOINHERIT PASSWORD :'gateway_svc_password';
ALTER ROLE eval_svc LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    NOINHERIT PASSWORD :'eval_svc_password';

-- The owner owns the database (and therefore, via pg_database_owner, the
-- public schema that holds the shared domains and enum types).
ALTER DATABASE :"dbname" OWNER TO aitl_owner;
