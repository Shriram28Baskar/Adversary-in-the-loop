#!/usr/bin/env sh
# Generate per-deployment secrets (fixture-grade local secrets; never production
# credentials — CLAUDE.md Security Principle #5). Output goes to
# deploy/secrets/generated/, which is git-ignored and must never be committed.
#
# Existing secrets are kept; pass --force to regenerate all of them.
#
# Permissions: the directory is 0700 (only the deploying user can reach the
# files on the host); each file is 0644 because non-swarm Compose bind-mounts
# file secrets with their host permissions, and the containers read them as
# non-root users (the postgres entrypoint after dropping privileges, the
# db-migrate job as 65534). A 0600 root-owned file would be unreadable there.
# Secrets are added to SECRETS as later phases introduce database roles and
# per-service tokens (ARCHITECTURE.md §24, §28).
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT_DIR="$SCRIPT_DIR/generated"

SECRETS="postgres_superuser_password
ingest_writer_password
intel_svc_password
scenario_gen_password
agent_svc_password
gateway_svc_password
eval_svc_password
aitl_migrator_password"

FORCE=0
if [ "${1:-}" = "--force" ]; then
  FORCE=1
elif [ $# -gt 0 ]; then
  echo "usage: $0 [--force]" >&2
  exit 2
fi

umask 077
mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR"

for name in $SECRETS; do
  target="$OUT_DIR/$name"
  if [ -e "$target" ] && [ "$FORCE" -eq 0 ]; then
    echo "keep     $name"
    continue
  fi
  # 48 random bytes, URL-safe base64 (64 printable characters, >= 32 required).
  python3 -c 'import secrets; print(secrets.token_urlsafe(48))' > "$target"
  chmod 644 "$target"
  echo "created  $name"
done
