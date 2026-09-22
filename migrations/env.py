"""Alembic environment for the Adversary-in-the-Loop database (ARCHITECTURE.md §24).

Ownership model:
- Migrations connect with the bootstrap administrator DSN from
  ``AITL_MIGRATION_DSN`` (or ``sqlalchemy.url`` set programmatically by tests),
  then ``SET ROLE aitl_owner`` so every object is owned by the NOLOGIN owner.
- No runtime service ever receives this DSN; runtime roles only get the
  privileges granted in migration 0012.
- Only online migrations are supported: offline SQL generation would bypass
  the ``SET ROLE`` ownership guarantee.
"""

from __future__ import annotations

import os

from alembic import context
from sqlalchemy import create_engine, pool, text

OWNER_ROLE = "aitl_owner"


def _database_url() -> str:
    configured = context.config.get_main_option("sqlalchemy.url")
    url = configured or os.environ.get("AITL_MIGRATION_DSN")
    if not url:
        raise RuntimeError("AITL_MIGRATION_DSN is not set")
    return url


def run_migrations_online() -> None:
    engine = create_engine(_database_url(), poolclass=pool.NullPool)
    with engine.connect() as connection:
        connection.execute(text(f"SET ROLE {OWNER_ROLE}"))
        connection.execute(text("SET lock_timeout = '10s'"))
        connection.commit()
        context.configure(
            connection=connection,
            version_table_schema="public",
            transaction_per_migration=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    raise RuntimeError("offline migrations are not supported (ownership requires SET ROLE)")
run_migrations_online()
