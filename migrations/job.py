"""Ephemeral database migration job (ADR-022; ARCHITECTURE.md §24, §31).

Runs once per deployment, applies the Alembic migrations, verifies the
database is back in its runtime security state, and exits. It is a deployment
job, not a runtime service: it opens no listening socket, serves no traffic,
and holds the only copy of the migrator credential outside the database.

Configuration (environment; the password only ever comes from a file):

    AITL_DB_HOST, AITL_DB_PORT (default 5432), AITL_DB_NAME,
    AITL_MIGRATION_USER (must be ``aitl_migrator``),
    AITL_MIGRATION_PASSWORD_FILE,
    AITL_MIGRATION_WAIT_SECONDS (default 60)

Exit codes: 0 migrated (or already at head); 1 migration failed; 2 database not
ready within the wait budget; 3 post-migration security check failed;
4 configuration or authentication error. Any non-zero code fails the
deployment step that ran the job.
"""

from __future__ import annotations

import json
import os
import sys
import time
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

import psycopg
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory

MIGRATOR_ROLE = "aitl_migrator"
OWNER_ROLE = "aitl_owner"
RUNTIME_ROLES = (
    "ingest_writer",
    "intel_svc",
    "scenario_gen",
    "agent_svc",
    "gateway_svc",
    "eval_svc",
)
ALEMBIC_INI = Path(__file__).resolve().parent / "alembic.ini"

EXIT_OK = 0
EXIT_MIGRATION_FAILED = 1
EXIT_DB_NOT_READY = 2
EXIT_POSTCONDITION_FAILED = 3
EXIT_CONFIG_ERROR = 4


class JobConfigError(ValueError):
    pass


def _log(event: str, **fields: Any) -> None:
    """One JSON line per event on stderr; never includes credentials."""
    record = {"ts": datetime.now(UTC).isoformat(), "event": event, **fields}
    print(json.dumps(record, ensure_ascii=True, sort_keys=True, default=str), file=sys.stderr)


class JobSettings:
    def __init__(
        self, *, host: str, port: int, dbname: str, user: str, password: str, wait_seconds: float
    ) -> None:
        self.host = host
        self.port = port
        self.dbname = dbname
        self.user = user
        self._password = password
        self.wait_seconds = wait_seconds

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> JobSettings:
        if "AITL_MIGRATION_PASSWORD" in env or "AITL_MIGRATION_DSN" in env:
            raise JobConfigError("inline migration credentials are not accepted; use a file")
        try:
            user = env["AITL_MIGRATION_USER"]
            host, dbname = env["AITL_DB_HOST"], env["AITL_DB_NAME"]
            password_file = Path(env["AITL_MIGRATION_PASSWORD_FILE"])
        except KeyError as exc:
            raise JobConfigError(f"missing setting {exc.args[0]}") from exc
        if user != MIGRATOR_ROLE:
            raise JobConfigError(f"migrations run only as {MIGRATOR_ROLE}, not {user!r}")
        try:
            password = password_file.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise JobConfigError(f"cannot read migration password file: {exc.strerror}") from exc
        if not password:
            raise JobConfigError("migration password file is empty")
        return cls(
            host=host,
            port=int(env.get("AITL_DB_PORT", "5432")),
            dbname=dbname,
            user=user,
            password=password,
            wait_seconds=float(env.get("AITL_MIGRATION_WAIT_SECONDS", "60")),
        )

    def conninfo(self) -> str:
        return psycopg.conninfo.make_conninfo(
            host=self.host,
            port=self.port,
            dbname=self.dbname,
            user=self.user,
            password=self._password,
            connect_timeout=5,
        )

    def sqlalchemy_url(self) -> str:
        return (
            f"postgresql+psycopg://{quote(self.user, safe='')}:{quote(self._password, safe='')}"
            f"@/{quote(self.dbname, safe='')}?host={quote(self.host, safe='/')}&port={self.port}"
        )


# Authentication/authorization refusals are permanent: fail fast, never retry.
_AUTH_FAILURE_MARKERS = (
    "password authentication failed",
    "pg_hba.conf rejects connection",
    "no pg_hba.conf entry",
    "does not exist",
)


def wait_for_database(settings: JobSettings) -> bool | None:
    """True when reachable; None on authentication/authorization failure; False on timeout."""
    deadline = time.monotonic() + settings.wait_seconds
    delay = 0.5
    while True:
        try:
            with psycopg.connect(settings.conninfo()) as conn:
                conn.execute("SELECT 1")
            return True
        except psycopg.OperationalError as exc:
            message = str(exc)
            if any(marker in message for marker in _AUTH_FAILURE_MARKERS):
                return None
            if time.monotonic() >= deadline:
                return False
            _log("migration.waiting_for_database", retry_in_seconds=delay)
            time.sleep(delay)
            delay = min(delay * 2, 5.0)


def run_migrations(settings: JobSettings) -> str:
    config = Config(str(ALEMBIC_INI))
    config.set_main_option("sqlalchemy.url", settings.sqlalchemy_url().replace("%", "%%"))
    command.upgrade(config, "head")
    head = ScriptDirectory.from_config(config).get_current_head()
    if head is None:
        raise RuntimeError("no migration head")
    return head


def verify_runtime_state(settings: JobSettings, expected_head: str) -> list[str]:
    """The database must be back in its runtime security state after migrating."""
    problems: list[str] = []
    with psycopg.connect(settings.conninfo(), autocommit=True) as conn:
        row = conn.execute(
            "SELECT current_user, r.rolsuper FROM pg_roles r WHERE r.rolname = session_user"
        ).fetchone()
        if row is None or row[0] != MIGRATOR_ROLE or row[1]:
            problems.append("job session is not the unprivileged migrator")
        # The migrator holds no object privileges of its own (INHERIT FALSE);
        # reading the version table requires the same SET ROLE as migrating.
        conn.execute(f"SET ROLE {OWNER_ROLE}")
        version = conn.execute("SELECT version_num FROM public.alembic_version").fetchall()
        conn.execute("RESET ROLE")
        if [row[0] for row in version] != [expected_head]:
            problems.append(f"alembic version {version} != {expected_head}")
        (owner_can_login,) = conn.execute(  # type: ignore[misc]
            "SELECT rolcanlogin FROM pg_roles WHERE rolname = %s", (OWNER_ROLE,)
        ).fetchone()
        if owner_can_login:
            problems.append(f"{OWNER_ROLE} can log in")
        (public_connect,) = conn.execute(  # type: ignore[misc]
            "SELECT has_database_privilege('public', current_database(), 'CONNECT')"
        ).fetchone()
        if public_connect:
            problems.append("PUBLIC can connect")
        members = conn.execute(
            "SELECT r.rolname FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.member "
            "JOIN pg_roles g ON g.oid = m.roleid WHERE g.rolname IN (%s, %s)",
            (OWNER_ROLE, MIGRATOR_ROLE),
        ).fetchall()
        leaked = sorted({str(member[0]) for member in members} & set(RUNTIME_ROLES))
        if leaked:
            problems.append(f"runtime roles hold owner/migrator membership: {leaked}")
        foreign_owned = conn.execute(
            "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname IN ('intel_raw', 'intel', 'agent', 'security', 'eval', 'ops') "
            "AND pg_get_userbyid(c.relowner) <> %s",
            (OWNER_ROLE,),
        ).fetchone()
        if foreign_owned is not None and foreign_owned[0]:
            problems.append("objects not owned by the NOLOGIN owner")
    return problems


def main(environ: Mapping[str, str] | None = None) -> int:
    env = os.environ if environ is None else environ
    try:
        settings = JobSettings.from_env(env)
    except (JobConfigError, ValueError) as exc:
        _log("migration.config_error", error=str(exc))
        return EXIT_CONFIG_ERROR

    _log("migration.started", host=settings.host, dbname=settings.dbname, user=settings.user)
    ready = wait_for_database(settings)
    if ready is None:
        _log("migration.authentication_failed")
        return EXIT_CONFIG_ERROR
    if not ready:
        _log("migration.database_not_ready", waited_seconds=settings.wait_seconds)
        return EXIT_DB_NOT_READY

    try:
        head = run_migrations(settings)
    except Exception as exc:  # noqa: BLE001 - any migration failure must fail the deployment
        _log("migration.failed", error_type=type(exc).__name__, error=str(exc)[:500])
        return EXIT_MIGRATION_FAILED

    problems = verify_runtime_state(settings, head)
    if problems:
        _log("migration.postcondition_failed", problems=problems)
        return EXIT_POSTCONDITION_FAILED
    _log("migration.completed", head=head)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
