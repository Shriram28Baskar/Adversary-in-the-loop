"""Database deployment configuration (ARCHITECTURE.md §24, §28; PRD SEC-003).

- pg_hba.conf admits only the runtime roles over the network, never the owner
  or the superuser, and uses no ``trust``; it is loaded by a real PostgreSQL
  server to prove it parses.
- The first-initialization hook passes exactly the runtime-role password
  variables that init-roles.sql consumes, from Compose secrets.
- init-roles.sql contains no literal password.
- Every runtime-role password is a Compose secret produced by generate.sh.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from tests.pg_harness import OWNER_ROLE, RUNTIME_ROLES, _as_server_user, _server_bindir

REPO_ROOT = Path(__file__).resolve().parents[2]
PG_HBA = REPO_ROOT / "deploy" / "postgres" / "pg_hba.conf"
INIT_SQL = REPO_ROOT / "deploy" / "postgres" / "init-roles.sql"
INIT_HOOK = REPO_ROOT / "deploy" / "postgres" / "10-init-roles.sh"
GENERATE = REPO_ROOT / "deploy" / "secrets" / "generate.sh"
COMPOSE = REPO_ROOT / "docker-compose.yml"


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


def test_hba_network_access_is_runtime_roles_only() -> None:
    host_rules = [r for r in _hba_rules() if r[0].startswith("host")]
    allowed = [r for r in host_rules if r[-1] != "reject"]
    assert len(allowed) == 1
    [rule] = allowed
    assert rule[1] == "aitl"
    assert set(rule[2].split(",")) == set(RUNTIME_ROLES)
    assert rule[-1] == "scram-sha-256"
    assert host_rules[-1] == ["host", "all", "all", "all", "reject"]


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
    expected = {f"{role}_password" for role in RUNTIME_ROLES}
    assert consumed == expected
    assert passed == expected
    assert "-f /etc/aitl/init-roles.sql" in INIT_HOOK.read_text()


def test_init_roles_contains_no_literal_password() -> None:
    text = INIT_SQL.read_text()
    assert not re.search(r"PASSWORD\s+'", text, re.IGNORECASE)
    assert re.search(r"CREATE ROLE aitl_owner NOLOGIN", text)


def test_every_role_password_is_a_generated_compose_secret(tmp_path: Path) -> None:
    compose = COMPOSE.read_text()
    shutil.copy(GENERATE, tmp_path / "generate.sh")
    subprocess.run(["sh", str(tmp_path / "generate.sh")], check=True, capture_output=True)
    generated = {p.name for p in (tmp_path / "generated").iterdir()}
    for role in RUNTIME_ROLES:
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
