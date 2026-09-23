"""Runtime isolation of the honeypot and the Log Shipper (P3; FR-004, FR-004a, FR-004b, FR-004d).

The repository's ``docker-compose.yml`` is brought up for real, in a
throwaway project, with only the images swapped for a local stand-in
(``runtime_standin``): networks, mounts, users, capabilities, security
options, tmpfs, secrets and cgroup limits all come from the real service
definitions. Probes then run *inside* the containers:

- the honeypot reaches nothing: not the database on any of its networks,
  not the Log Shipper, not sandbox- or orchestration-style networks, not the
  internet or the host; the failure is "no route" (ENETUNREACH), never
  "refused", which would mean a reachable host;
- the Log Shipper reaches the database on ingest-net (the control proving
  the probe works) and nothing else;
- both run non-root with no capabilities, no-new-privileges, read-only
  roots and the declared cgroup limits; nothing publishes a port;
- a live mutation (attaching the honeypot to ingest-net) is detected.

Requires a Docker daemon. These are security acceptance tests (CLAUDE.md
Testing Rules), so an unavailable daemon fails them rather than skipping.
"""

from __future__ import annotations

import json
import secrets
import subprocess
import textwrap
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from tests.security import runtime_standin

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"
VERSIONS_ENV = REPO_ROOT / "deploy" / "versions.env"
SECRET_NAMES = (
    "postgres_superuser_password",
    "ingest_writer_password",
    "intel_svc_password",
    "scenario_gen_password",
    "agent_svc_password",
    "gateway_svc_password",
    "eval_svc_password",
    "aitl_migrator_password",
)
NO_ROUTE = {"ENETUNREACH", "EHOSTUNREACH", "timeout", "resolve_failed"}
LISTENER = textwrap.dedent(
    """
    import socket, sys
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", int(sys.argv[1])))
    s.listen(16)
    while True:
        conn, _ = s.accept()
        conn.close()
    """
)
SLEEPER = "import time\ntime.sleep(3600)"
CONTAINER_TMP_PROBE = "/tmp/probe"  # noqa: S108 - a path inside the probed container
PROBE = textwrap.dedent(
    """
    import errno, json, os, socket, sys
    targets = json.loads(sys.argv[1])
    paths = json.loads(sys.argv[2])
    out = {"connect": {}, "write": {}, "facts": {}}
    for name, (host, port) in targets.items():
        try:
            infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        except OSError:
            out["connect"][name] = "resolve_failed"
            continue
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        try:
            s.connect(infos[0][4])
            out["connect"][name] = "connected"
        except socket.timeout:
            out["connect"][name] = "timeout"
        except OSError as exc:
            out["connect"][name] = errno.errorcode.get(exc.errno, str(exc.errno))
        finally:
            s.close()
    out["udp"] = {}
    for name, (host, port) in targets.items():
        try:
            address = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)[0][4]
        except OSError:
            out["udp"][name] = "resolve_failed"
            continue
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            u.sendto(b"probe", address)
            out["udp"][name] = "sent"
        except OSError as exc:
            out["udp"][name] = errno.errorcode.get(exc.errno, str(exc.errno))
        finally:
            u.close()
    for path in paths:
        try:
            with open(path, "w") as handle:
                handle.write("probe")
            os.unlink(path)
            out["write"][path] = "ok"
        except OSError as exc:
            out["write"][path] = errno.errorcode.get(exc.errno, str(exc.errno))
    status = open("/proc/self/status").read()
    fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
    out["facts"]["uid"] = os.getuid()
    out["facts"]["gid"] = os.getgid()
    out["facts"]["cap_eff"] = fields["CapEff"].strip()
    out["facts"]["cap_bnd"] = fields["CapBnd"].strip()
    out["facts"]["no_new_privs"] = fields["NoNewPrivs"].strip()
    def read(path):
        try:
            return open("/sys/fs/cgroup/" + path).read().strip()
        except OSError:
            return None
    if read("cgroup.controllers") is not None:  # cgroup v2
        for key in ("memory.max", "pids.max", "cpu.max"):
            out["facts"][key] = read(key)
    else:  # cgroup v1, normalized to the v2 spelling
        out["facts"]["memory.max"] = read("memory/memory.limit_in_bytes")
        out["facts"]["pids.max"] = read("pids/pids.max")
        quota, period = read("cpu/cpu.cfs_quota_us"), read("cpu/cpu.cfs_period_us")
        out["facts"]["cpu.max"] = f"{quota} {period}"
    out["facts"]["mounts"] = open("/proc/self/mounts").read()
    has_secrets = os.path.isdir("/run/secrets")
    out["facts"]["secrets"] = sorted(os.listdir("/run/secrets")) if has_secrets else []
    print(json.dumps(out))
    """
)


def _override(image: str, secrets_dir: Path) -> str:
    """Swap images/commands only; every security-relevant key stays as committed."""

    def command(script: str, *args: str) -> str:
        return json.dumps(["-c", script, *args])

    secret_lines = "\n".join(f"  {name}:\n    file: {secrets_dir / name}" for name in SECRET_NAMES)
    return (
        textwrap.dedent(
            f"""
        services:
          db:
            image: {image}
            user: "65534:65534"
            entrypoint: ["{runtime_standin.PYTHON}"]
            command: {command(LISTENER, "5432")}
            healthcheck:
              test: ["CMD", "{runtime_standin.PYTHON}", "-c",
                     "import socket; socket.create_connection(('127.0.0.1', 5432), 1)"]
              interval: 1s
              timeout: 2s
              retries: 30
          honeypot:
            image: {image}
            entrypoint: ["{runtime_standin.PYTHON}"]
            command: {command(LISTENER, "2222")}
          log-shipper:
            image: {image}
            build: !reset null
            pull_policy: never
            entrypoint: ["{runtime_standin.PYTHON}"]
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
class Stack:
    project: str
    files: list[str]
    extra_containers: list[str]
    extra_networks: list[str]
    targets: dict[str, tuple[str, int]]

    def compose(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        command = ["docker", "compose", "-p", self.project, "--env-file", str(VERSIONS_ENV)]
        for file in self.files:
            command += ["-f", file]
        return subprocess.run(
            [*command, *args], capture_output=True, text=True, check=check, cwd=REPO_ROOT
        )

    def container(self, service: str) -> str:
        return self.compose("ps", "-q", service).stdout.strip()

    def inspect(self, service: str) -> dict[str, Any]:
        out = subprocess.run(
            ["docker", "inspect", self.container(service)],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        result: dict[str, Any] = json.loads(out)[0]
        return result

    def probe(self, service: str, write_paths: list[str] | None = None) -> dict[str, Any]:
        result = self.compose(
            "exec",
            "-T",
            service,
            runtime_standin.PYTHON,
            "-c",
            PROBE,
            json.dumps(self.targets),
            json.dumps(write_paths or []),
        )
        probed: dict[str, Any] = json.loads(result.stdout)
        return probed


def _ip(inspected: dict[str, Any], network: str) -> str:
    address: str = inspected["NetworkSettings"]["Networks"][network]["IPAddress"]
    assert address
    return address


def _docker(*args: str) -> str:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=True
    ).stdout.strip()


@pytest.fixture(scope="module")
def stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Stack]:
    if not runtime_standin.docker_available():
        pytest.fail("runtime isolation tests need a reachable Docker daemon")
    workdir = tmp_path_factory.mktemp("runtime-isolation")
    image = runtime_standin.build(workdir)
    secrets_dir = workdir / "secrets"
    secrets_dir.mkdir()
    for name in SECRET_NAMES:
        (secrets_dir / name).write_text(secrets.token_hex(16))
        (secrets_dir / name).chmod(0o644)
    override = workdir / "override.yml"
    override.write_text(_override(image, secrets_dir))
    project = f"aitlp3{uuid.uuid4().hex[:10]}"
    stack = Stack(project, [str(COMPOSE_FILE), str(override)], [], [], {})
    try:
        stack.compose(
            "--profile", "honeypot-isolation", "up", "-d", "--wait", "db", "log-shipper", "honeypot"
        )
        db = stack.inspect("db")
        honeypot = stack.inspect("honeypot")
        # Stand-ins for networks no P3 service joins yet: an internal network like
        # sandbox-net and an ordinary bridge like the outbound networks.
        for suffix, internal in (("sandboxprobe", True), ("bridgeprobe", False)):
            network = f"{project}_{suffix}"
            _docker("network", "create", *(["--internal"] if internal else []), network)
            stack.extra_networks.append(network)
            name = f"{project}-{suffix}"
            _docker(
                "run",
                "-d",
                "--name",
                name,
                "--network",
                network,
                "--user",
                "65534:65534",
                image,
                "-c",
                LISTENER,
                "8080",
            )
            stack.extra_containers.append(name)
        sandbox_ip = _ip(
            json.loads(_docker("inspect", f"{project}-sandboxprobe"))[0], f"{project}_sandboxprobe"
        )
        bridge_ip = _ip(
            json.loads(_docker("inspect", f"{project}-bridgeprobe"))[0], f"{project}_bridgeprobe"
        )
        gateway = json.loads(_docker("network", "inspect", "bridge"))[0]["IPAM"]["Config"][0]
        stack.targets = {
            "db_by_name": ("db", 5432),
            "db_ingest_net": (_ip(db, f"{project}_ingest-net"), 5432),
            "db_core_net": (_ip(db, f"{project}_core-net"), 5432),
            "db_migrate_net": (_ip(db, f"{project}_migrate-net"), 5432),
            "honeypot_by_name": ("honeypot", 2222),
            "honeypot_ip": (_ip(honeypot, f"{project}_honeypot-net"), 2222),
            "log_shipper_by_name": ("log-shipper", 8080),
            "sandbox_style_net": (sandbox_ip, 8080),
            "bridge_net": (bridge_ip, 8080),
            "docker_host_gateway": (gateway["Gateway"], 22),
            "internet_ip": ("1.1.1.1", 443),
            "internet_dns_ip": ("8.8.8.8", 53),
            "internet_name": ("example.com", 443),
        }
        yield stack
    finally:
        for name in stack.extra_containers:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
        stack.compose(
            "--profile", "honeypot-isolation", "down", "-v", "--remove-orphans", check=False
        )
        for network in stack.extra_networks:
            subprocess.run(["docker", "network", "rm", network], capture_output=True, check=False)


@pytest.fixture(scope="module")
def honeypot_probe(stack: Stack) -> dict[str, Any]:
    return stack.probe(
        "honeypot",
        [
            "/probe",
            "/cowrie/cowrie-git/etc/probe",
            "/cowrie/cowrie-git/var/log/cowrie/probe",
            "/cowrie/cowrie-git/var/lib/cowrie/probe",
        ],
    )


@pytest.fixture(scope="module")
def shipper_probe(stack: Stack) -> dict[str, Any]:
    return stack.probe(
        "log-shipper",
        ["/probe", "/srv/aitl/source/probe.json", "/srv/aitl/state/probe", CONTAINER_TMP_PROBE],
    )


# --- honeypot: zero egress -------------------------------------------------------------


@pytest.mark.parametrize(
    "target",
    [
        "db_by_name",
        "db_ingest_net",
        "db_core_net",
        "db_migrate_net",
        "log_shipper_by_name",
        "sandbox_style_net",
        "bridge_net",
        "docker_host_gateway",
        "internet_ip",
        "internet_dns_ip",
        "internet_name",
    ],
)
def test_honeypot_reaches_nothing(honeypot_probe: dict[str, Any], target: str) -> None:
    assert honeypot_probe["connect"][target] in NO_ROUTE, honeypot_probe["connect"]


def test_honeypot_ip_targets_fail_with_no_route(honeypot_probe: dict[str, Any]) -> None:
    """No route at all (not merely a closed port): the netns has no path out."""
    for target in ("db_ingest_net", "db_core_net", "db_migrate_net", "internet_ip", "bridge_net"):
        assert honeypot_probe["connect"][target] == "ENETUNREACH", honeypot_probe["connect"]


@pytest.mark.parametrize(
    "target", ["db_ingest_net", "db_core_net", "bridge_net", "internet_ip", "internet_dns_ip"]
)
def test_honeypot_cannot_send_udp(honeypot_probe: dict[str, Any], target: str) -> None:
    """FR-004a: arbitrary outbound UDP is blocked at the network layer too."""
    assert honeypot_probe["udp"][target] == "ENETUNREACH", honeypot_probe["udp"]


def test_udp_probe_control(shipper_probe: dict[str, Any]) -> None:
    """Control: the same UDP probe sends where a route exists."""
    assert shipper_probe["udp"]["db_ingest_net"] == "sent"
    assert shipper_probe["udp"]["internet_ip"] == "ENETUNREACH"


def test_honeypot_hardening_at_runtime(honeypot_probe: dict[str, Any]) -> None:
    facts = honeypot_probe["facts"]
    assert (facts["uid"], facts["gid"]) == (999, 999)
    assert int(facts["cap_eff"], 16) == 0
    assert int(facts["cap_bnd"], 16) == 0
    assert facts["no_new_privs"] == "1"
    assert facts["memory.max"] == str(512 * 1024 * 1024)
    assert facts["pids.max"] == "256"
    assert facts["cpu.max"] == "100000 100000"
    assert facts["secrets"] == []
    assert "docker.sock" not in facts["mounts"]
    writes = honeypot_probe["write"]
    assert writes["/probe"] == "EROFS"
    assert writes["/cowrie/cowrie-git/etc/probe"] == "EROFS"
    assert writes["/cowrie/cowrie-git/var/log/cowrie/probe"] == "ok"  # its one-way outlet
    assert writes["/cowrie/cowrie-git/var/lib/cowrie/probe"] == "ok"  # bounded tmpfs


def test_honeypot_container_config(stack: Stack) -> None:
    host = stack.inspect("honeypot")["HostConfig"]
    assert host["Privileged"] is False
    assert host["PortBindings"] in ({}, None)
    assert host["PublishAllPorts"] is False
    assert host["PidMode"] in ("", "private")
    assert host["IpcMode"] != "host"
    assert host["ReadonlyRootfs"] is True
    assert host["CapDrop"] == ["ALL"]
    assert not host.get("CapAdd")
    assert "no-new-privileges:true" in host["SecurityOpt"]
    networks = stack.inspect("honeypot")["NetworkSettings"]["Networks"]
    assert set(networks) == {f"{stack.project}_honeypot-net"}


# --- Log Shipper: only the database ------------------------------------------------------


def test_shipper_reaches_the_database_on_ingest_net(shipper_probe: dict[str, Any]) -> None:
    """Control: the same probe does connect where a path exists."""
    assert shipper_probe["connect"]["db_by_name"] == "connected"
    assert shipper_probe["connect"]["db_ingest_net"] == "connected"


@pytest.mark.parametrize(
    "target",
    [
        "honeypot_by_name",
        "honeypot_ip",
        "db_core_net",
        "db_migrate_net",
        "sandbox_style_net",
        "bridge_net",
        "docker_host_gateway",
        "internet_ip",
        "internet_name",
    ],
)
def test_shipper_reaches_nothing_else(shipper_probe: dict[str, Any], target: str) -> None:
    assert shipper_probe["connect"][target] in NO_ROUTE, shipper_probe["connect"]


def test_shipper_hardening_and_mounts_at_runtime(shipper_probe: dict[str, Any]) -> None:
    facts = shipper_probe["facts"]
    assert (facts["uid"], facts["gid"]) == (65534, 65534)
    assert int(facts["cap_eff"], 16) == 0
    assert facts["no_new_privs"] == "1"
    assert facts["memory.max"] == str(256 * 1024 * 1024)
    assert facts["pids.max"] == "64"
    assert facts["cpu.max"] == "50000 100000"
    assert facts["secrets"] == ["ingest_writer_password"]
    assert "cowrie" not in facts["mounts"]  # never mounts the honeypot volume here
    assert "docker.sock" not in facts["mounts"]
    writes = shipper_probe["write"]
    assert writes["/probe"] == "EROFS"
    assert writes["/srv/aitl/source/probe.json"] == "EROFS"  # corpus is read-only
    assert writes["/srv/aitl/state/probe"] == "ok"
    assert writes[CONTAINER_TMP_PROBE] == "ok"


def test_no_container_publishes_a_port(stack: Stack) -> None:
    for service in ("db", "honeypot", "log-shipper"):
        host = stack.inspect(service)["HostConfig"]
        assert host["PortBindings"] in ({}, None), service
        assert host["PublishAllPorts"] is False, service


def test_honeypot_log_volume_is_read_only_through_a_ro_mount(stack: Stack) -> None:
    """The one-way outlet (ADR-009): a ``:ro`` reader cannot write back into it."""
    volume = f"{stack.project}_honeypot-logs"
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--user",
            "65534:65534",
            "-v",
            f"{volume}:/logs:ro",
            runtime_standin.TAG,
            "-c",
            "import errno\ntry:\n open('/logs/x','w')\n print('ok')\n"
            "except OSError as e:\n print(errno.errorcode[e.errno])",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == "EROFS"


# --- mutation: a weakened boundary is detected ---------------------------------------------


def test_probe_detects_honeypot_attached_to_ingest_net(stack: Stack) -> None:
    network = f"{stack.project}_ingest-net"
    container = stack.container("honeypot")
    _docker("network", "connect", network, container)
    try:
        weakened = stack.probe("honeypot")
    finally:
        _docker("network", "disconnect", network, container)
    assert weakened["connect"]["db_ingest_net"] == "connected"
    assert stack.probe("honeypot")["connect"]["db_ingest_net"] == "ENETUNREACH"
