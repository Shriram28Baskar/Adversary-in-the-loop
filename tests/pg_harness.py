"""Real PostgreSQL for database security tests (engineering plan §8; P1).

Database permission, trigger, and constraint tests must run against real
PostgreSQL — never SQLite or mocks. Two ways to obtain it:

1. ``AITL_TEST_PG_ADMIN_DSN`` — a superuser DSN for a disposable cluster
   (CI uses a digest-pinned PostgreSQL service container).
2. Otherwise a throwaway local cluster is created with the PostgreSQL server
   binaries found on this machine (``initdb``/``pg_ctl``), listening only on a
   private unix socket, with SCRAM password authentication for every role and
   no TCP listener. When running as root the server runs as ``nobody``.

If neither is available the tests fail with an explicit error; they are never
skipped.
"""

from __future__ import annotations

import glob
import os
import secrets
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

import psycopg
from alembic import command
from alembic.config import Config

REPO_ROOT = Path(__file__).resolve().parents[1]
INIT_ROLES_SQL = REPO_ROOT / "deploy" / "postgres" / "init-roles.sql"
ALEMBIC_INI = REPO_ROOT / "migrations" / "alembic.ini"

OWNER_ROLE = "aitl_owner"
RUNTIME_ROLES = (
    "ingest_writer",
    "intel_svc",
    "scenario_gen",
    "agent_svc",
    "gateway_svc",
    "eval_svc",
)


class PostgresUnavailableError(RuntimeError):
    pass


def _server_bindir() -> Path | None:
    candidates: list[Path] = []
    initdb = shutil.which("initdb")
    if initdb:
        candidates.append(Path(initdb).parent)
    candidates.extend(Path(p) for p in sorted(glob.glob("/usr/lib/postgresql/*/bin"), reverse=True))
    for directory in candidates:
        if (directory / "initdb").exists() and (directory / "pg_ctl").exists():
            return directory
    return None


def _psql() -> str:
    found = shutil.which("psql")
    if found:
        return found
    bindir = _server_bindir()
    if bindir and (bindir / "psql").exists():
        return str(bindir / "psql")
    raise PostgresUnavailableError("psql not found")


@dataclass
class Cluster:
    """Connection facts for the admin (superuser) of a disposable cluster."""

    host: str
    port: int
    admin_user: str
    admin_password: str
    passwords: dict[str, str] = field(default_factory=dict)

    def conninfo(self, dbname: str, user: str, password: str) -> str:
        return psycopg.conninfo.make_conninfo(
            host=self.host, port=self.port, dbname=dbname, user=user, password=password
        )

    def admin_conninfo(self, dbname: str = "postgres") -> str:
        return self.conninfo(dbname, self.admin_user, self.admin_password)

    def sqlalchemy_admin_url(self, dbname: str) -> str:
        user = quote(self.admin_user, safe="")
        password = quote(self.admin_password, safe="")
        return (
            f"postgresql+psycopg://{user}:{password}@/{dbname}"
            f"?host={quote(self.host, safe='/')}&port={self.port}"
        )

    def connect(self, dbname: str, role: str) -> psycopg.Connection[tuple[object, ...]]:
        return psycopg.connect(self.conninfo(dbname, role, self.passwords[role]))

    def admin(self, dbname: str = "postgres") -> psycopg.Connection[tuple[object, ...]]:
        return psycopg.connect(self.admin_conninfo(dbname), autocommit=True)

    # --- database lifecycle ---------------------------------------------------

    def create_database(self, dbname: str) -> None:
        with self.admin() as conn:
            conn.execute(f'CREATE DATABASE "{dbname}"')
        self.init_roles(dbname)

    def drop_database(self, dbname: str) -> None:
        with self.admin() as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{dbname}" WITH (FORCE)')

    def init_roles(self, dbname: str) -> None:
        """Run deploy/postgres/init-roles.sql exactly as a deployment would."""
        args = [_psql(), "-X", "-q", "-v", "ON_ERROR_STOP=1", "-v", f"dbname={dbname}"]
        for role in RUNTIME_ROLES:
            args += ["-v", f"{role}_password={self.passwords[role]}"]
        args += ["-f", str(INIT_ROLES_SQL), self.admin_conninfo(dbname)]
        subprocess.run(args, check=True, capture_output=True, text=True)

    def alembic_config(self, dbname: str) -> Config:
        config = Config(str(ALEMBIC_INI))
        config.set_main_option(
            "sqlalchemy.url", self.sqlalchemy_admin_url(dbname).replace("%", "%%")
        )
        return config

    def upgrade(self, dbname: str, revision: str = "head") -> None:
        command.upgrade(self.alembic_config(dbname), revision)

    def downgrade(self, dbname: str, revision: str) -> None:
        command.downgrade(self.alembic_config(dbname), revision)


def _as_server_user(args: list[str]) -> list[str]:
    if os.geteuid() == 0:
        return ["runuser", "-u", "nobody", "--", *args]
    return args


@contextmanager
def _local_cluster() -> Iterator[Cluster]:
    bindir = _server_bindir()
    if bindir is None:
        raise PostgresUnavailableError(
            "No PostgreSQL server binaries found and AITL_TEST_PG_ADMIN_DSN is not set; "
            "database security tests require a real PostgreSQL."
        )
    base = Path(tempfile.mkdtemp(prefix="aitl-pg-", dir="/tmp"))
    base.chmod(0o755)
    data, sock = base / "data", base / "sock"
    sock.mkdir(mode=0o700)
    admin_password = secrets.token_urlsafe(32)
    pwfile = base / "pwfile"
    pwfile.write_text(admin_password + "\n")
    if os.geteuid() == 0:
        shutil.chown(sock, "nobody")
        shutil.chown(pwfile, "nobody")
        shutil.chown(base, "nobody")
    pwfile.chmod(0o600)
    log = base / "server.log"
    try:
        subprocess.run(
            _as_server_user(
                [
                    str(bindir / "initdb"),
                    "-D",
                    str(data),
                    "-U",
                    "aitl_admin",
                    f"--pwfile={pwfile}",
                    "--auth-local=scram-sha-256",
                    "--auth-host=reject",
                    "-E",
                    "UTF8",
                    "--locale=C",
                ]
            ),
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            _as_server_user(
                [
                    str(bindir / "pg_ctl"),
                    "-D",
                    str(data),
                    "-l",
                    str(log),
                    "-w",
                    "-o",
                    f"-c listen_addresses='' -c unix_socket_directories={sock} -c fsync=off "
                    "-c full_page_writes=off",
                    "start",
                ]
            ),
            check=True,
            capture_output=True,
            text=True,
        )
        yield Cluster(
            host=str(sock), port=5432, admin_user="aitl_admin", admin_password=admin_password
        )
    finally:
        subprocess.run(
            _as_server_user([str(bindir / "pg_ctl"), "-D", str(data), "-m", "immediate", "stop"]),
            check=False,
            capture_output=True,
        )
        shutil.rmtree(base, ignore_errors=True)


@contextmanager
def cluster() -> Iterator[Cluster]:
    """Yield a disposable cluster with random passwords for every runtime role."""
    passwords = {role: secrets.token_urlsafe(32) for role in RUNTIME_ROLES}
    dsn = os.environ.get("AITL_TEST_PG_ADMIN_DSN")
    if dsn:
        params = psycopg.conninfo.conninfo_to_dict(dsn)
        yield Cluster(
            host=str(params.get("host", "localhost")),
            port=int(str(params.get("port") or 5432)),
            admin_user=str(params["user"]),
            admin_password=str(params["password"]),
            passwords=passwords,
        )
        return
    with _local_cluster() as local:
        local.passwords = passwords
        yield local
