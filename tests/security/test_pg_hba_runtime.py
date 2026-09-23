"""ingest_writer authentication is bound to ingest-net, proven at runtime (FR-004b; §24, §28).

A real PostgreSQL 16 server (the host's server binaries, see
``runtime_standin``) runs inside the repository's own ``db`` service
definition, with the committed ``deploy/postgres/pg_hba.conf`` and
``init-roles.sql`` mounted exactly as Compose mounts them, the roles created
from the Compose secrets, and ``scram-sha-256`` passwords. Clients then
connect with ``psql`` from containers on each Compose network, so the
server sees each network's real source address:

- ingest-net + ingest_writer + its password: accepted (and from the real
  ``log-shipper`` service definition);
- core-net, migrate-net (wrong subnets) + ingest_writer: rejected by
  pg_hba.conf even with the correct password;
- honeypot-net and a sandbox-style network: no route to the db at all, and
  rejected by pg_hba.conf even if the db were attached (mutation);
- wrong or another service's password: authentication fails;
- the migrator stays bound to migrate-net; other runtime roles unchanged.

Requires a Docker daemon (fails rather than skips, like the isolation tests).
"""

from __future__ import annotations

import json
import secrets
import subprocess
import textwrap
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from tests.security import runtime_standin

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"
VERSIONS_ENV = REPO_ROOT / "deploy" / "versions.env"
SECRET_ROLES = (
    "ingest_writer",
    "intel_svc",
    "scenario_gen",
    "agent_svc",
    "gateway_svc",
    "eval_svc",
    "aitl_migrator",
)
SECRET_NAMES = ("postgres_superuser_password", *(f"{r}_password" for r in SECRET_ROLES))
LISTENER = textwrap.dedent(
    """
    import socket, sys
    s = socket.socket(); s.bind(("0.0.0.0", int(sys.argv[1]))); s.listen(4)
    while True:
        s.accept()[0].close()
    """
)
SLEEPER = "import time\ntime.sleep(3600)"


def _db_init(bindir: str) -> str:
    """First-initialization equivalent of deploy/postgres/10-init-roles.sh."""
    return textwrap.dedent(
        f"""
        import os, subprocess, time
        B, D = {bindir!r}, "/tmp/pgdata"
        run = lambda *a: subprocess.run(list(a), check=True, capture_output=True)
        run(B + "/initdb", "-D", D, "-U", "postgres", "-A", "reject",
            "--locale=C", "--encoding=UTF8")
        run(B + "/pg_ctl", "-D", D, "-w", "-l", "/tmp/pg.log", "-o",
            "-c hba_file=/etc/aitl/pg_hba.conf -c password_encryption=scram-sha-256 "
            "-c listen_addresses=* -c unix_socket_directories=/tmp", "start")
        psql = [B + "/psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-h", "/tmp", "-U", "postgres"]
        run(*psql, "-d", "postgres", "-c", "CREATE DATABASE aitl")
        variables = []
        for role in {SECRET_ROLES!r}:
            with open("/run/secrets/" + role + "_password") as handle:
                variables += ["-v", role + "_password=" + handle.read().strip()]
        run(*psql, "-d", "aitl", "-v", "dbname=aitl", *variables,
            "-f", "/etc/aitl/init-roles.sql")
        open("/tmp/ready", "w").close()
        while True:
            time.sleep(3600)
        """
    )


def _override(pg_image: str, py_image: str, secrets_dir: Path, bindir: str) -> str:
    def command(script: str, *args: str) -> str:
        return json.dumps(["-c", script, *args])

    secret_lines = "\n".join(f"  {name}:\n    file: {secrets_dir / name}" for name in SECRET_NAMES)
    python = runtime_standin.PYTHON
    return (
        textwrap.dedent(
            f"""
        services:
          db:
            image: {pg_image}
            user: "{runtime_standin.PG_UID}:{runtime_standin.PG_UID}"
            entrypoint: ["{python}"]
            command: {command(_db_init(bindir))}
            healthcheck:
              test: ["CMD", "{python}", "-c", "import os; assert os.path.exists('/tmp/ready')"]
              interval: 1s
              timeout: 2s
              retries: 60
          honeypot:
            image: {py_image}
            entrypoint: ["{python}"]
            command: {command(LISTENER, "2222")}
          log-shipper:
            image: {pg_image}
            build: !reset null
            pull_policy: never
            entrypoint: ["{python}"]
            command: {command(SLEEPER)}
            healthcheck:
              disable: true
        secrets:
        """
        )
        + secret_lines
        + "\n"
    )


@dataclass
class Cluster:
    project: str
    files: list[str]
    passwords: dict[str, str]
    bindir: str
    db_ip: dict[str, str] = field(default_factory=dict)
    extra_networks: list[str] = field(default_factory=list)

    def compose(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        command = ["docker", "compose", "-p", self.project, "--env-file", str(VERSIONS_ENV)]
        for file in self.files:
            command += ["-f", file]
        return subprocess.run(
            [*command, *args], capture_output=True, text=True, check=check, cwd=REPO_ROOT
        )

    def container(self, service: str) -> str:
        return self.compose("ps", "-q", service).stdout.strip()

    def network(self, name: str) -> str:
        return f"{self.project}_{name}"


def _classify(result: subprocess.CompletedProcess[str]) -> str:
    output = result.stdout + result.stderr
    if result.returncode == 0:
        return "ok:" + result.stdout.strip()
    if "pg_hba.conf rejects connection" in output:
        return "hba_reject"
    if "password authentication failed" in output or "no password supplied" in output:
        return "auth_failed"
    if (
        "timeout expired" in output
        or "No route to host" in output
        or "Network is unreachable" in output
    ):
        return "unreachable"
    return "error:" + output.strip()[-200:]


def _psql_args(bindir: str, host: str, role: str) -> list[str]:
    conninfo = f"host={host} port=5432 dbname=aitl user={role} connect_timeout=3"
    return [f"{bindir}/psql", conninfo, "-X", "-A", "-t", "-w", "-c", "SELECT current_user"]


def _connect(cluster: Cluster, network: str, db_ip: str, role: str, password: str | None) -> str:
    """psql from a fresh unprivileged container attached to ``network`` only."""
    env = ["-e", f"PGPASSWORD={password}"] if password is not None else []
    args = _psql_args(cluster.bindir, db_ip, role)
    result = subprocess.run(
        [
            "docker", "run", "--rm", "--network", network, "--user", "65534:65534",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", *env,
            "--entrypoint", args[0], runtime_standin.PG_TAG, *args[1:],
        ],
        capture_output=True, text=True, check=False, timeout=60,
    )  # fmt: skip
    return _classify(result)


def _docker(*args: str) -> str:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=True
    ).stdout.strip()


@pytest.fixture(scope="module")
def cluster(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Cluster]:
    if not runtime_standin.docker_available():
        pytest.fail("runtime pg_hba tests need a reachable Docker daemon")
    workdir = tmp_path_factory.mktemp("pg-hba-runtime")
    pg_image = runtime_standin.build(workdir, postgres=True)
    py_image = runtime_standin.build(workdir)
    bindir = runtime_standin.postgres_bindir()
    secrets_dir = workdir / "secrets"
    secrets_dir.mkdir()
    passwords = {}
    for name in SECRET_NAMES:
        value = secrets.token_urlsafe(24)
        (secrets_dir / name).write_text(value)
        (secrets_dir / name).chmod(0o644)
        passwords[name.removesuffix("_password")] = value
    override = workdir / "override.yml"
    override.write_text(_override(pg_image, py_image, secrets_dir, bindir))
    project = f"aitlhba{uuid.uuid4().hex[:10]}"
    cluster = Cluster(project, [str(COMPOSE_FILE), str(override)], passwords, bindir)
    try:
        cluster.compose(
            "--profile", "honeypot-isolation", "up", "-d", "--wait", "db", "log-shipper", "honeypot"
        )
        inspected: dict[str, Any] = json.loads(_docker("inspect", cluster.container("db")))[0]
        for name, settings in inspected["NetworkSettings"]["Networks"].items():
            cluster.db_ip[name.removeprefix(f"{project}_")] = settings["IPAddress"]
        sandbox = cluster.network("sandboxprobe")
        _docker("network", "create", "--internal", sandbox)
        cluster.extra_networks.append(sandbox)
        yield cluster
    finally:
        cluster.compose(
            "--profile", "honeypot-isolation", "down", "-v", "--remove-orphans", check=False
        )
        for network in cluster.extra_networks:
            subprocess.run(["docker", "network", "rm", network], capture_output=True, check=False)


def test_db_joins_exactly_its_three_networks(cluster: Cluster) -> None:
    assert set(cluster.db_ip) == {"core-net", "ingest-net", "migrate-net"}
    assert cluster.db_ip["ingest-net"].startswith("10.231.253.")


# --- 1. correct source -------------------------------------------------------------------


def test_ingest_writer_accepted_from_ingest_net(cluster: Cluster) -> None:
    ip = cluster.db_ip["ingest-net"]
    outcome = _connect(
        cluster,
        cluster.network("ingest-net"),
        ip,
        "ingest_writer",
        cluster.passwords["ingest_writer"],
    )
    assert outcome == "ok:ingest_writer"


def test_log_shipper_service_authenticates_as_ingest_writer(cluster: Cluster) -> None:
    """The real log-shipper service definition (its user, secret and network)."""
    script = (
        "import os, subprocess, sys\n"
        "secret = open('/run/secrets/ingest_writer_password').read().strip()\n"
        "env = dict(os.environ, PGPASSWORD=secret)\n"
        "r = subprocess.run(sys.argv[1:], env=env, capture_output=True, text=True)\n"
        "print(r.returncode); print(r.stdout.strip()); print(r.stderr.strip())\n"
    )
    args = _psql_args(cluster.bindir, "db", "ingest_writer")
    result = cluster.compose(
        "exec", "-T", "log-shipper", runtime_standin.PYTHON, "-c", script, *args
    )
    code, user = result.stdout.splitlines()[:2]
    assert (code, user) == ("0", "ingest_writer"), result.stdout


# --- 2-5. wrong sources ---------------------------------------------------------------


@pytest.mark.parametrize("network", ["core-net", "migrate-net"])
def test_ingest_writer_rejected_from_other_db_networks(cluster: Cluster, network: str) -> None:
    """The db is reachable from these networks, but pg_hba.conf refuses the source."""
    outcome = _connect(
        cluster,
        cluster.network(network),
        cluster.db_ip[network],
        "ingest_writer",
        cluster.passwords["ingest_writer"],
    )
    assert outcome == "hba_reject"


@pytest.mark.parametrize("network", ["honeypot-net", "sandboxprobe"])
def test_ingest_writer_rejected_from_honeypot_and_sandbox_networks(
    cluster: Cluster, network: str
) -> None:
    """No route at all; and even with the db attached (mutation), pg_hba.conf refuses."""
    full = cluster.network(network)
    password = cluster.passwords["ingest_writer"]
    for target in cluster.db_ip.values():
        assert _connect(cluster, full, target, "ingest_writer", password) == "unreachable"
    db = cluster.container("db")
    _docker("network", "connect", full, db)
    try:
        inspected = json.loads(_docker("inspect", db))[0]
        attached_ip = inspected["NetworkSettings"]["Networks"][full]["IPAddress"]
        outcome = _connect(cluster, full, attached_ip, "ingest_writer", password)
    finally:
        _docker("network", "disconnect", full, db)
    assert outcome == "hba_reject"


# --- 6. no ingest credential ----------------------------------------------------------------


UNKNOWN_CREDENTIAL = "unknown"  # a guess no role holds


@pytest.mark.parametrize(
    "credential_of", [None, UNKNOWN_CREDENTIAL, "intel_svc", "aitl_migrator", "postgres_superuser"]
)
def test_ingest_writer_requires_its_own_password(
    cluster: Cluster, credential_of: str | None
) -> None:
    supplied: str | None = None
    if credential_of == UNKNOWN_CREDENTIAL:
        supplied = secrets.token_urlsafe(24)
    elif credential_of is not None:
        supplied = cluster.passwords[credential_of]
    outcome = _connect(
        cluster,
        cluster.network("ingest-net"),
        cluster.db_ip["ingest-net"],
        "ingest_writer",
        supplied,
    )
    assert outcome == "auth_failed"


def test_honeypot_service_holds_no_database_credential(cluster: Cluster) -> None:
    listing = cluster.compose(
        "exec", "-T", "honeypot", runtime_standin.PYTHON, "-c",
        "import os; print(os.path.isdir('/run/secrets') and os.listdir('/run/secrets'))",
    )  # fmt: skip
    assert listing.stdout.strip() in ("False", "[]")


# --- unchanged behaviour: other runtime roles and the migrator ------------------------------


@pytest.mark.parametrize(
    "role", ["intel_svc", "scenario_gen", "agent_svc", "gateway_svc", "eval_svc"]
)
def test_other_runtime_roles_still_accepted_on_core_net(cluster: Cluster, role: str) -> None:
    outcome = _connect(
        cluster,
        cluster.network("core-net"),
        cluster.db_ip["core-net"],
        role,
        cluster.passwords[role],
    )
    assert outcome == f"ok:{role}"


def test_migrator_still_bound_to_migrate_net(cluster: Cluster) -> None:
    password = cluster.passwords["aitl_migrator"]
    accepted = _connect(
        cluster,
        cluster.network("migrate-net"),
        cluster.db_ip["migrate-net"],
        "aitl_migrator",
        password,
    )
    assert accepted == "ok:aitl_migrator"
    for network in ("core-net", "ingest-net"):
        outcome = _connect(
            cluster, cluster.network(network), cluster.db_ip[network], "aitl_migrator", password
        )
        assert outcome == "hba_reject", network


def test_ingest_writer_session_has_no_elevated_attributes(cluster: Cluster) -> None:
    """The subnet binding changed authentication only; the role is unchanged."""
    query = (
        "SELECT rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, rolreplication, "
        "pg_has_role(current_user, 'aitl_owner', 'MEMBER'), "
        "pg_has_role(current_user, 'aitl_migrator', 'MEMBER') "
        "FROM pg_roles WHERE rolname = current_user"
    )
    args = _psql_args(cluster.bindir, cluster.db_ip["ingest-net"], "ingest_writer")
    args[-1] = query
    result = subprocess.run(
        [
            "docker", "run", "--rm", "--network", cluster.network("ingest-net"),
            "--user", "65534:65534", "-e", f"PGPASSWORD={cluster.passwords['ingest_writer']}",
            "--entrypoint", args[0], runtime_standin.PG_TAG, *args[1:],
        ],
        capture_output=True, text=True, check=True, timeout=60,
    )  # fmt: skip
    assert result.stdout.strip() == "f|f|f|f|f|f|f"
