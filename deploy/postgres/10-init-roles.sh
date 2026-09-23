#!/bin/sh
# First-initialization hook for the db container (/docker-entrypoint-initdb.d).
# Creates the owner, runtime and migrator roles with passwords read from the per-role
# Compose secrets (deploy/secrets/generate.sh), via deploy/postgres/init-roles.sql.
# Runs only when the data directory is first created.
set -eu

secret() {
  cat "/run/secrets/$1_password"
}

psql -X -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v dbname="$POSTGRES_DB" \
  -v ingest_writer_password="$(secret ingest_writer)" \
  -v intel_svc_password="$(secret intel_svc)" \
  -v scenario_gen_password="$(secret scenario_gen)" \
  -v agent_svc_password="$(secret agent_svc)" \
  -v gateway_svc_password="$(secret gateway_svc)" \
  -v eval_svc_password="$(secret eval_svc)" \
  -v aitl_migrator_password="$(secret aitl_migrator)" \
  -f /etc/aitl/init-roles.sql
