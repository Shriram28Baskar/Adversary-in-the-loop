"""Per-role database engines for runtime services (ARCHITECTURE.md §24).

Each service connects only as its own runtime role. Connection settings come
from the environment, with the password read from a per-deployment secret file:

    AITL_DB_HOST, AITL_DB_PORT (default 5432), AITL_DB_NAME,
    AITL_DB_USER, AITL_DB_PASSWORD_FILE

The factory refuses to build an engine for any user other than the service's
expected runtime role — in particular the NOLOGIN owner ``aitl_owner`` or any
admin account — and ``verify_runtime_identity`` confirms on the live
connection that the session user is that role and holds no elevated
attributes. Runtime services never receive migration or owner credentials.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import quote

from sqlalchemy import Engine, create_engine, text

__all__ = [
    "OWNER_ROLE",
    "RUNTIME_ROLES",
    "DatabaseSettings",
    "RuntimeIdentityError",
    "create_role_engine",
    "verify_runtime_identity",
]

OWNER_ROLE = "aitl_owner"
MIGRATOR_ROLE = "aitl_migrator"  # deployment-only role (ADR-022); never a runtime identity
RUNTIME_ROLES = frozenset(
    {"ingest_writer", "intel_svc", "scenario_gen", "agent_svc", "gateway_svc", "eval_svc"}
)


class RuntimeIdentityError(RuntimeError):
    """The configured or connected database identity is not the expected runtime role."""


class DatabaseSettings:
    def __init__(self, *, host: str, port: int, dbname: str, user: str, password: str) -> None:
        self.host = host
        self.port = port
        self.dbname = dbname
        self.user = user
        self._password = password

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> DatabaseSettings:
        env = os.environ if environ is None else environ
        try:
            host, dbname, user = env["AITL_DB_HOST"], env["AITL_DB_NAME"], env["AITL_DB_USER"]
            password_file = Path(env["AITL_DB_PASSWORD_FILE"])
        except KeyError as exc:
            raise RuntimeIdentityError(f"missing database setting {exc.args[0]}") from exc
        if "AITL_DB_PASSWORD" in env or "AITL_DB_DSN" in env:
            raise RuntimeIdentityError("inline database credentials are not accepted; use a file")
        password = password_file.read_text(encoding="utf-8").strip()
        return cls(
            host=host,
            port=int(env.get("AITL_DB_PORT", "5432")),
            dbname=dbname,
            user=user,
            password=password,
        )

    def url(self) -> str:
        return (
            f"postgresql+psycopg://{quote(self.user, safe='')}:{quote(self._password, safe='')}"
            f"@/{quote(self.dbname, safe='')}?host={quote(self.host, safe='/')}&port={self.port}"
        )

    def __repr__(self) -> str:  # never expose the password
        return f"DatabaseSettings(host={self.host!r}, dbname={self.dbname!r}, user={self.user!r})"


def create_role_engine(expected_role: str, settings: DatabaseSettings) -> Engine:
    """Create an engine for ``expected_role``; refuse any other identity."""
    if expected_role not in RUNTIME_ROLES:
        raise RuntimeIdentityError(f"{expected_role!r} is not a runtime role")
    if settings.user != expected_role:
        raise RuntimeIdentityError(
            f"configured database user {settings.user!r} is not the expected role {expected_role!r}"
        )
    engine = create_engine(settings.url(), pool_pre_ping=True)
    verify_runtime_identity(engine, expected_role)
    return engine


def verify_runtime_identity(engine: Engine, expected_role: str) -> None:
    """Confirm the live session is ``expected_role`` with no elevated attributes."""
    with engine.connect() as connection:
        row = connection.execute(
            text(
                "SELECT session_user, current_user, r.rolsuper, r.rolcreaterole, r.rolcreatedb, "
                "r.rolbypassrls, r.rolreplication, "
                "pg_has_role(session_user, :owner, 'MEMBER') AS owner_member, "
                "pg_has_role(session_user, :migrator, 'MEMBER') AS migrator_member "
                "FROM pg_roles r WHERE r.rolname = session_user"
            ),
            {"owner": OWNER_ROLE, "migrator": MIGRATOR_ROLE},
        ).one()
    session_user, current_user, *elevated, owner_member, migrator_member = row
    if session_user != expected_role or current_user != expected_role:
        raise RuntimeIdentityError(f"connected as {session_user!r}, expected {expected_role!r}")
    if any(elevated) or owner_member or migrator_member:
        raise RuntimeIdentityError(f"role {expected_role!r} has elevated privileges")
