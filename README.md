# Adversary-in-the-loop

Real-world AI agent security proving ground. Read, in order of authority:
`PROJECT_VISION.md` (intent), `PRD.md` (requirements), `ARCHITECTURE.md`
(architecture), `CLAUDE.md` (engineering rules).

## Development

Requirements: [uv](https://docs.astral.sh/uv/) 0.8.17, Python 3.11, Docker with Compose v2,
and PostgreSQL 16 server binaries (`initdb`, `pg_ctl`, `psql`) for the database tests.

```sh
uv sync --locked                     # install the pinned environment
uv run --locked ruff format --check .
uv run --locked ruff check .
uv run --locked mypy                 # strict
uv run --locked pytest               # unit, topology, secret-hygiene, database security tests
```

Local stack (single-host profile, ARCHITECTURE.md §31):

```sh
deploy/secrets/generate.sh           # per-deployment secrets -> deploy/secrets/generated/ (git-ignored)
docker compose --env-file deploy/versions.env up
```

All images are pinned by digest in `deploy/versions.env`; Compose refuses to
start without it. The network topology in `docker-compose.yml` is a security
boundary and is verified by `tests/security/test_compose_topology.py`.

## Database

PostgreSQL schema, roles and privileges are the persistence security boundary
(ARCHITECTURE.md §24). Schema objects are created only by the Alembic
migrations in `migrations/`, owned by the NOLOGIN role `aitl_owner`; runtime
services connect only as their own least-privilege role
(`aitl_common.db.engine`) and never receive migration or owner credentials.

- Roles: `deploy/postgres/init-roles.sql` (run once per cluster by the
  bootstrap superuser; `deploy/postgres/10-init-roles.sh` does this in Compose).
- Migrations: run by the migration job with the bootstrap admin DSN, which
  switches to `aitl_owner` before creating objects:
  `AITL_MIGRATION_DSN=postgresql+psycopg://... uv run --locked alembic -c migrations/alembic.ini upgrade head`
- Tests use real PostgreSQL only: a disposable local cluster started from the
  server binaries, or the cluster named by `AITL_TEST_PG_ADMIN_DSN` (CI uses a
  digest-pinned PostgreSQL service container).
