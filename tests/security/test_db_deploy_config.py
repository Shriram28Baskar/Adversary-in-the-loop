"""Database deployment configuration (ARCHITECTURE.md §24, §28; PRD SEC-003).

- pg_hba.conf admits the runtime roles over the network and the deployment
  role ``aitl_migrator`` only from the migrate-net subnet (ADR-022); never the
  owner or the superuser, and no ``trust``. A real PostgreSQL server loads the
  file and its TCP decisions are exercised.
- The first-initialization hook passes exactly the role password variables
  that init-roles.sql consumes, from Compose secrets.
- init-roles.sql contains no literal password.
- Every login-role password is a Compose secret produced by generate.sh.
- The migration job image is digest-pinned and installs only hash-locked
  dependencies exported from uv.lock.
"""

from __future__ import annotations

import os
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import psycopg
import pytest
from psycopg import sql

from tests.pg_harness import (
    INIT_ROLES_SQL,
    MIGRATOR_ROLE,
    OWNER_ROLE,
    RUNTIME_ROLES,
    _as_server_user,
    _psql,
    _server_bindir,
)
from tests.security.compose_policy import INGEST_NET_SUBNET, MIGRATE_NET_SUBNET

REPO_ROOT = Path(__file__).resolve().parents[2]
PG_HBA = REPO_ROOT / "deploy" / "postgres" / "pg_hba.conf"
INIT_SQL = REPO_ROOT / "deploy" / "postgres" / "init-roles.sql"
INIT_HOOK = REPO_ROOT / "deploy" / "postgres" / "10-init-roles.sh"
GENERATE = REPO_ROOT / "deploy" / "secrets" / "generate.sh"
COMPOSE = REPO_ROOT / "docker-compose.yml"
MIGRATE_DOCKERFILE = REPO_ROOT / "deploy" / "migrate" / "Dockerfile"
MIGRATE_REQUIREMENTS = REPO_ROOT / "deploy" / "migrate" / "requirements.txt"
LOGIN_ROLES = (*RUNTIME_ROLES, MIGRATOR_ROLE)
INGEST_ROLE = "ingest_writer"
ANYWHERE_ROLES = tuple(r for r in RUNTIME_ROLES if r != INGEST_ROLE)
HBA_REJECT = re.escape("pg_hba.conf rejects connection")


def _hba_rules() -> list[list[str]]:
    rules = []
    for line in PG_HBA.read_text().splitlines():
        stripped = line.split("#", 1)[0].strip()
        if stripped:
            rules.append(stripped.split())
    return rules


def test_hba_never_trusts_and_never_admits_owner() -> None:
    for rule in _hba_rules():
        assert rule[-1] != "trust", rule
        users = rule[2].split(",")
        assert OWNER_ROLE not in users, rule


def test_hba_superuser_is_local_peer_only() -> None:
    superuser_rules = [r for r in _hba_rules() if "postgres" in r[2].split(",")]
    assert superuser_rules == [["local", "all", "postgres", "peer"]]


def test_hba_network_access_is_runtime_roles_and_subnet_bound_ingest_and_migrator() -> None:
    host_rules = [r for r in _hba_rules() if r[0].startswith("host")]
    allowed = [r for r in host_rules if r[-1] != "reject"]
    assert allowed == [
        ["host", "aitl", ",".join(ANYWHERE_ROLES), "all", "scram-sha-256"],
        ["host", "aitl", INGEST_ROLE, INGEST_NET_SUBNET, "scram-sha-256"],
        ["host", "aitl", MIGRATOR_ROLE, MIGRATE_NET_SUBNET, "scram-sha-256"],
    ]
    assert host_rules[-1] == ["host", "all", "all", "all", "reject"]


def test_hba_admits_ingest_writer_only_from_its_subnet() -> None:
    """ingest_writer appears in exactly one accepting rule, bound to ingest-net."""
    rules = [r for r in _hba_rules() if r[-1] != "reject"]
    ingest = [r for r in rules if INGEST_ROLE in r[2].split(",") or r[2] == "all"]
    assert ingest == [["host", "aitl", INGEST_ROLE, INGEST_NET_SUBNET, "scram-sha-256"]]


def test_hba_migrator_subnet_matches_compose_migrate_net() -> None:
    """pg_hba.conf and docker-compose.yml must name the same migrate-net subnet."""
    assert f"subnet: {MIGRATE_NET_SUBNET}" in COMPOSE.read_text()


def test_hba_ingest_subnet_matches_compose_ingest_net() -> None:
    """pg_hba.conf and docker-compose.yml must name the same ingest-net subnet."""
    compose = COMPOSE.read_text()
    ingest_block = compose.split("  ingest-net:", 1)[1].split("\n  core-net:", 1)[0]
    assert f"subnet: {INGEST_NET_SUBNET}" in ingest_block
    assert INGEST_NET_SUBNET != MIGRATE_NET_SUBNET


def test_hba_loads_in_real_postgres() -> None:
    bindir = _server_bindir()
    assert bindir is not None, "PostgreSQL server binaries are required"
    base = Path(tempfile.mkdtemp(prefix="aitl-hba-", dir="/tmp"))
    base.chmod(0o755)
    data, sock, hba = base / "data", base / "sock", base / "pg_hba.conf"
    sock.mkdir(mode=0o700)
    shutil.copy(PG_HBA, hba)
    hba.chmod(0o644)
    if shutil.which("runuser") and _as_server_user(["x"])[0] == "runuser":
        shutil.chown(base, "nobody")
        shutil.chown(sock, "nobody")
    try:
        subprocess.run(
            _as_server_user([str(bindir / "initdb"), "-D", str(data), "-A", "reject", "-U", "x"]),
            check=True,
            capture_output=True,
        )
        started = subprocess.run(
            _as_server_user(
                [
                    str(bindir / "pg_ctl"),
                    "-D",
                    str(data),
                    "-w",
                    "-l",
                    str(base / "log"),
                    "-o",
                    f"-c listen_addresses='' -c unix_socket_directories={sock} -c hba_file={hba}",
                    "start",
                ]
            ),
            capture_output=True,
            text=True,
            check=False,
        )
        log = (base / "log").read_text() if (base / "log").exists() else ""
        assert started.returncode == 0, log
        assert "could not load" not in log
    finally:
        subprocess.run(
            _as_server_user([str(bindir / "pg_ctl"), "-D", str(data), "-m", "immediate", "stop"]),
            capture_output=True,
            check=False,
        )
        shutil.rmtree(base, ignore_errors=True)


def test_init_hook_passes_exactly_the_role_password_variables() -> None:
    consumed = set(re.findall(r":'([a-z_]+_password)'", INIT_SQL.read_text()))
    passed = set(re.findall(r"-v ([a-z_]+_password)=", INIT_HOOK.read_text()))
    expected = {f"{role}_password" for role in LOGIN_ROLES}
    assert consumed == expected
    assert passed == expected
    assert "-f /etc/aitl/init-roles.sql" in INIT_HOOK.read_text()


def test_init_roles_contains_no_literal_password() -> None:
    text = INIT_SQL.read_text()
    assert not re.search(r"PASSWORD\s+'", text, re.IGNORECASE)
    assert re.search(r"CREATE ROLE aitl_owner NOLOGIN", text)
    assert "GRANT aitl_owner TO aitl_migrator WITH INHERIT FALSE, SET TRUE;" in text


def test_every_role_password_is_a_generated_compose_secret(tmp_path: Path) -> None:
    compose = COMPOSE.read_text()
    shutil.copy(GENERATE, tmp_path / "generate.sh")
    subprocess.run(["sh", str(tmp_path / "generate.sh")], check=True, capture_output=True)
    generated = {p.name for p in (tmp_path / "generated").iterdir()}
    for role in LOGIN_ROLES:
        name = f"{role}_password"
        assert f"- {name}\n" in compose, name
        assert f"file: deploy/secrets/generated/{name}\n" in compose, name
        assert name in generated, name


def test_db_config_mounts_are_read_only() -> None:
    compose = COMPOSE.read_text()
    for mount in (
        "./deploy/postgres/pg_hba.conf:/etc/aitl/pg_hba.conf:ro",
        "./deploy/postgres/init-roles.sql:/etc/aitl/init-roles.sql:ro",
        "./deploy/postgres/10-init-roles.sh:/docker-entrypoint-initdb.d/10-init-roles.sh:ro",
    ):
        assert mount in compose
    assert "hba_file=/etc/aitl/pg_hba.conf" in compose


def test_migration_image_is_pinned_and_hash_locked() -> None:
    dockerfile = MIGRATE_DOCKERFILE.read_text()
    froms = re.findall(r"^FROM\s+(\S+)", dockerfile, re.MULTILINE)
    assert len(froms) == 1
    assert re.search(r"@sha256:[0-9a-f]{64}$", froms[0]), froms
    assert "--require-hashes" in dockerfile
    assert re.search(r"^USER 65534:65534$", dockerfile, re.MULTILINE)
    assert "EXPOSE" not in dockerfile
    # Only the migrations directory is copied in: no application packages.
    assert re.findall(r"^COPY\s+(\S+)", dockerfile, re.MULTILINE) == [
        "deploy/migrate/requirements.txt",
        "migrations",
    ]


def test_migration_requirements_match_lockfile() -> None:
    exported = subprocess.run(
        [
            "uv",
            "export",
            "--locked",
            "--only-group",
            "migrate",
            "--no-emit-project",
            "--format",
            "requirements.txt",
            "--no-header",
        ],
        capture_output=True,
        text=True,
        check=True,
        cwd=REPO_ROOT,
    ).stdout
    committed = MIGRATE_REQUIREMENTS.read_text()
    body = "\n".join(line for line in committed.splitlines() if not line.startswith("#"))
    assert (
        body.strip()
        == "\n".join(line for line in exported.splitlines() if not line.startswith("#")).strip()
    )
    assert "--hash=sha256:" in committed


# --- The real pg_hba.conf, enforced by a real server over TCP ------------------------


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@contextmanager
def _server_with_repo_hba() -> Iterator[tuple[Path, int, dict[str, str], Path]]:
    """Start a server whose hba_file is a copy of deploy/postgres/pg_hba.conf.

    A permissive setup hba creates the roles (via init-roles.sql) and the
    ``aitl`` database over the unix socket; then the repository file is swapped
    in and reloaded, so every later connection is decided by it alone.
    """
    bindir = _server_bindir()
    assert bindir is not None, "PostgreSQL server binaries are required"
    base = Path(tempfile.mkdtemp(prefix="aitl-hba-tcp-", dir="/tmp"))
    base.chmod(0o755)
    data, sock, hba = base / "data", base / "sock", base / "pg_hba.conf"
    sock.mkdir(mode=0o700)
    hba.write_text("local all all trust\n")
    hba.chmod(0o644)
    if os.geteuid() == 0:
        shutil.chown(base, "nobody")
        shutil.chown(sock, "nobody")
    port = _free_port()
    passwords = {role: secrets.token_urlsafe(24) for role in LOGIN_ROLES}
    try:
        subprocess.run(
            _as_server_user(
                [str(bindir / "initdb"), "-D", str(data), "-A", "reject", "-U", "postgres"]
            ),
            check=True,
            capture_output=True,
        )
        subprocess.run(
            _as_server_user(
                [
                    str(bindir / "pg_ctl"),
                    "-D",
                    str(data),
                    "-w",
                    "-l",
                    str(base / "log"),
                    "-o",
                    f"-c listen_addresses=127.0.0.1 -c port={port} "
                    f"-c unix_socket_directories={sock} -c hba_file={hba}",
                    "start",
                ]
            ),
            check=True,
            capture_output=True,
        )
        setup = f"host={sock} port={port} user=postgres dbname=postgres"
        with psycopg.connect(setup, autocommit=True) as conn:
            conn.execute("CREATE DATABASE aitl")
        args = [_psql(), "-X", "-q", "-v", "ON_ERROR_STOP=1", "-v", "dbname=aitl"]
        for role, password in passwords.items():
            args += ["-v", f"{role}_password={password}"]
        args += ["-f", str(INIT_ROLES_SQL), f"host={sock} port={port} user=postgres dbname=aitl"]
        subprocess.run(args, check=True, capture_output=True, text=True)
        with psycopg.connect(setup, autocommit=True) as conn:
            conn.execute(
                sql.SQL("ALTER ROLE postgres PASSWORD {}").format(
                    sql.Literal(passwords[RUNTIME_ROLES[0]])
                )
            )
        shutil.copy(PG_HBA, hba)
        hba.chmod(0o644)
        _pg_reload(data)
        # From here on, the setup trust rule is gone.
        yield data, port, passwords, hba
    finally:
        subprocess.run(
            _as_server_user([str(bindir / "pg_ctl"), "-D", str(data), "-m", "immediate", "stop"]),
            capture_output=True,
            check=False,
        )
        shutil.rmtree(base, ignore_errors=True)


def _pg_reload(data: Path) -> None:
    bindir = _server_bindir()
    assert bindir is not None
    subprocess.run(
        _as_server_user([str(bindir / "pg_ctl"), "-D", str(data), "reload"]),
        check=True,
        capture_output=True,
    )
    # pg_ctl reload only signals; give the postmaster time to apply the new rules.
    time.sleep(0.5)


def _tcp(port: int, user: str, password: str, dbname: str = "aitl") -> str:
    return psycopg.conninfo.make_conninfo(
        host="127.0.0.1",
        port=port,
        user=user,
        password=password,
        dbname=dbname,
        connect_timeout=5,
    )


def test_repo_hba_enforced_over_tcp() -> None:
    with _server_with_repo_hba() as (data, port, passwords, hba):
        # Runtime roles other than ingest_writer: admitted with their SCRAM
        # password from any source, to aitl only.
        for role in ANYWHERE_ROLES:
            with psycopg.connect(_tcp(port, role, passwords[role])) as conn:
                assert conn.execute("SELECT current_user").fetchone() == (role,)
        with pytest.raises(psycopg.OperationalError, match="password authentication failed"):
            psycopg.connect(_tcp(port, "intel_svc", "wrong-password"))
        with pytest.raises(psycopg.OperationalError, match=HBA_REJECT):
            psycopg.connect(_tcp(port, "intel_svc", passwords["intel_svc"], dbname="postgres"))

        # The migrator's correct password is refused from outside migrate-net.
        with pytest.raises(psycopg.OperationalError, match=HBA_REJECT):
            psycopg.connect(_tcp(port, MIGRATOR_ROLE, passwords[MIGRATOR_ROLE]))
        # The owner and the superuser are never admitted over the network.
        with pytest.raises(psycopg.OperationalError, match=HBA_REJECT):
            psycopg.connect(_tcp(port, OWNER_ROLE, passwords[MIGRATOR_ROLE]))
        with pytest.raises(psycopg.OperationalError, match=HBA_REJECT):
            psycopg.connect(_tcp(port, "postgres", passwords[RUNTIME_ROLES[0]]))

        # ingest_writer's correct password is refused from outside ingest-net.
        with pytest.raises(psycopg.OperationalError, match=HBA_REJECT):
            psycopg.connect(_tcp(port, INGEST_ROLE, passwords[INGEST_ROLE]))

        # Control: the only thing refusing the migrator is its source address.
        # Point the migrator rule at 127.0.0.1/32 and it is admitted.
        hba.write_text(PG_HBA.read_text().replace(MIGRATE_NET_SUBNET, "127.0.0.1/32"))
        _pg_reload(data)
        with psycopg.connect(_tcp(port, MIGRATOR_ROLE, passwords[MIGRATOR_ROLE])) as conn:
            assert conn.execute("SELECT current_user").fetchone() == (MIGRATOR_ROLE,)
        with pytest.raises(psycopg.OperationalError, match=HBA_REJECT):
            psycopg.connect(_tcp(port, INGEST_ROLE, passwords[INGEST_ROLE]))

        # Control: likewise for ingest_writer - its source address alone refuses
        # it; from an admitted source the password is still required.
        hba.write_text(PG_HBA.read_text().replace(INGEST_NET_SUBNET, "127.0.0.1/32"))
        _pg_reload(data)
        with psycopg.connect(_tcp(port, INGEST_ROLE, passwords[INGEST_ROLE])) as conn:
            assert conn.execute("SELECT current_user").fetchone() == (INGEST_ROLE,)
        with pytest.raises(psycopg.OperationalError, match="password authentication failed"):
            psycopg.connect(_tcp(port, INGEST_ROLE, passwords["intel_svc"]))
        with pytest.raises(psycopg.OperationalError, match=HBA_REJECT):
            psycopg.connect(_tcp(port, MIGRATOR_ROLE, passwords[MIGRATOR_ROLE]))
