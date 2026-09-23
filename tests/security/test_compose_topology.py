"""Compose topology security tests (ARCHITECTURE.md §28, §31; PRD FR-004d, SEC-002).

Two layers:

1. The repository's ``docker-compose.yml`` is rendered by Docker Compose itself
   (default profile and all profiles) and checked against the §28 policy.
2. The policy checker is exercised against a complete reference topology that
   includes every service the architecture defines, and against one mutation per
   rule, proving each boundary violation is actually detected. Services are added
   to the real file only in the phase that implements them, so layer 2 is what
   proves the checker will hold them to §28 when they arrive.
"""

from __future__ import annotations

import copy
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.security import compose_policy

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"
VERSIONS_ENV = REPO_ROOT / "deploy" / "versions.env"


def _render(*profile_args: str) -> dict[str, Any]:
    result = subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            str(VERSIONS_ENV),
            "-f",
            str(COMPOSE_FILE),
            *profile_args,
            "config",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        check=True,
        cwd=REPO_ROOT,
    )
    rendered: dict[str, Any] = json.loads(result.stdout)
    return rendered


@pytest.fixture(scope="module")
def rendered_default() -> dict[str, Any]:
    return _render()


@pytest.fixture(scope="module")
def rendered_all() -> dict[str, Any]:
    return _render("--profile", "*")


@pytest.fixture(scope="module")
def raw_compose() -> dict[str, Any]:
    loaded: dict[str, Any] = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
    return loaded


# --- Layer 1: the real docker-compose.yml -----------------------------------------


def test_real_compose_declares_section_28_networks(raw_compose: dict[str, Any]) -> None:
    assert compose_policy.check_declared_networks(raw_compose) == []


def test_real_compose_services_comply(
    rendered_all: dict[str, Any], rendered_default: dict[str, Any]
) -> None:
    assert compose_policy.check_services(rendered_all, rendered_default) == []


def test_real_compose_internal_networks_rendered_internal(rendered_all: dict[str, Any]) -> None:
    for name, network in rendered_all.get("networks", {}).items():
        if name in compose_policy.INTERNAL_NETWORKS:
            assert network.get("internal") is True, name


def test_real_compose_publishes_no_port_except_loopback_dashboard(
    rendered_all: dict[str, Any],
) -> None:
    for name, service in rendered_all["services"].items():
        for port in service.get("ports") or []:
            assert name == "dashboard", f"{name} publishes {port}"
            assert port.get("host_ip") == "127.0.0.1", port


def test_real_compose_honeypot_not_started_by_default(rendered_default: dict[str, Any]) -> None:
    assert "honeypot" not in rendered_default["services"]


def _pinned_variables() -> list[str]:
    return [
        line.split("=", 1)[0]
        for line in VERSIONS_ENV.read_text().splitlines()
        if line and not line.startswith("#")
    ]


def test_real_compose_requires_pinned_versions_file() -> None:
    """Without deploy/versions.env the image reference must fail loudly, not float."""
    result = subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "config", "--format", "json"],
        capture_output=True,
        text=True,
        check=False,
        cwd=REPO_ROOT,
        env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(Path.home())},
    )
    assert result.returncode != 0
    assert "must be set via deploy/versions.env" in result.stderr


@pytest.mark.parametrize("variable", _pinned_variables())
def test_every_pinned_image_variable_is_required(tmp_path: Path, variable: str) -> None:
    """Dropping any single pinned value fails rendering, naming that value."""
    lines = [
        line
        for line in VERSIONS_ENV.read_text().splitlines()
        if not line.startswith(f"{variable}=")
    ]
    partial = tmp_path / "versions.env"
    partial.write_text("\n".join(lines) + "\n")
    result = subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            str(partial),
            "-f",
            str(COMPOSE_FILE),
            "--profile",
            "*",
            "config",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        check=False,
        cwd=REPO_ROOT,
        env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(Path.home())},
    )
    assert result.returncode != 0
    assert variable in result.stderr


def test_versions_file_pins_every_image_by_digest() -> None:
    for variable in _pinned_variables():
        value = next(
            line.split("=", 1)[1]
            for line in VERSIONS_ENV.read_text().splitlines()
            if line.startswith(f"{variable}=")
        )
        assert compose_policy._DIGEST_PINNED.search(value), variable


def test_real_compose_uses_file_secrets_for_db(rendered_all: dict[str, Any]) -> None:
    db = rendered_all["services"]["db"]
    assert db["environment"]["POSTGRES_PASSWORD_FILE"].startswith("/run/secrets/")
    assert "POSTGRES_PASSWORD" not in db["environment"]


# --- Layer 2: reference topology and one mutation per rule ------------------------

_PINNED = "example/image:1.0@sha256:" + "a" * 64


def _svc(*networks: str, **extra: Any) -> dict[str, Any]:
    service: dict[str, Any] = {"image": _PINNED, "networks": {name: None for name in networks}}
    service.update(extra)
    return service


def _hardened(mem: int, cpus: float, pids: int, user: str) -> dict[str, Any]:
    return {
        "read_only": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "user": user,
        "mem_limit": str(mem),
        "cpus": cpus,
        "pids_limit": pids,
    }


def _reference() -> tuple[dict[str, Any], dict[str, Any]]:
    """The full ARCHITECTURE.md §28 single-host topology in rendered form."""
    networks: dict[str, Any] = {
        name: {"name": f"aitl_{name}", "internal": name in compose_policy.INTERNAL_NETWORKS}
        for name in compose_policy.DECLARED_NETWORKS
    }
    networks["migrate-net"]["ipam"] = {"config": [{"subnet": compose_policy.MIGRATE_NET_SUBNET}]}
    services = {
        "honeypot": _svc(
            "honeypot-net",
            profiles=["honeypot-isolation"],
            restart="no",
            **_hardened(512 * 1024 * 1024, 1.0, 256, "999:999"),
            volumes=[
                {
                    "type": "bind",
                    "source": "/repo/honeypot/cowrie/etc",
                    "target": compose_policy.COWRIE_ETC,
                    "read_only": True,
                },
                {
                    "type": "volume",
                    "source": "honeypot-logs",
                    "target": compose_policy.COWRIE_LOG_DIR,
                },
            ],
            tmpfs=[
                f"{compose_policy.COWRIE_VAR}:size=16m",
                "/cowrie/cowrie-git/var/lib/cowrie:size=64m",
            ],
        ),
        "log-shipper": _svc(
            "ingest-net",
            **_hardened(256 * 1024 * 1024, 0.5, 64, "65534:65534"),
            volumes=[
                {
                    "type": "volume",
                    "source": "honeypot-logs",
                    "target": "/logs",
                    "read_only": True,
                }
            ],
            environment={"INGEST_PASSWORD_FILE": "/run/secrets/ingest_writer_password"},
        ),
        "db": _svc(
            "core-net",
            "ingest-net",
            "migrate-net",
            secrets=[{"source": "aitl_migrator_password"}, {"source": "intel_svc_password"}],
        ),
        "intel-service": _svc("core-net"),
        "agent-runtime": _svc("core-net", "orchestration-net"),
        "gateway-service": _svc("core-net", "sandbox-net", "llm-egress"),
        "eval-service": _svc("core-net"),
        "dashboard": _svc(
            "core-net",
            "operator-net",
            ports=[
                {
                    "mode": "ingress",
                    "host_ip": "127.0.0.1",
                    "target": 3000,
                    "published": "3000",
                    "protocol": "tcp",
                }
            ],
        ),
        "container-api-proxy": _svc(
            "orchestration-net",
            volumes=[
                {
                    "type": "bind",
                    "source": "/var/run/docker.sock",
                    "target": "/var/run/docker.sock",
                    "read_only": True,
                }
            ],
        ),
        "db-migrate": {
            "build": {"context": ".", "dockerfile": "deploy/migrate/Dockerfile"},
            "profiles": ["deploy-jobs"],
            "networks": {"migrate-net": None},
            "restart": "no",
            "read_only": True,
            "user": "65534:65534",
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "secrets": [{"source": "aitl_migrator_password"}],
            "environment": {"AITL_MIGRATION_PASSWORD_FILE": "/run/secrets/aitl_migrator_password"},
        },
    }
    volumes = {
        "honeypot-logs": {"driver": "local", "driver_opts": {"type": "tmpfs", "o": "size=256m"}}
    }
    rendered_all = {"services": services, "networks": networks, "volumes": volumes}
    rendered_default = {
        "services": {k: v for k, v in services.items() if k not in ("honeypot", "db-migrate")},
        "networks": networks,
    }
    return rendered_all, rendered_default


def _raw_reference() -> dict[str, Any]:
    return {
        "networks": {
            name: ({"internal": True} if name in compose_policy.INTERNAL_NETWORKS else {})
            for name in compose_policy.DECLARED_NETWORKS
        }
    }


def test_reference_topology_is_compliant() -> None:
    rendered_all, rendered_default = _reference()
    assert compose_policy.check_services(rendered_all, rendered_default) == []
    assert compose_policy.check_declared_networks(_raw_reference()) == []


def _violations_after(mutate: Any) -> list[str]:
    rendered_all, rendered_default = _reference()
    rendered_all = copy.deepcopy(rendered_all)
    rendered_default = copy.deepcopy(rendered_default)
    mutate(rendered_all, rendered_default)
    return compose_policy.check_services(rendered_all, rendered_default)


def _assert_detected(violations: list[str], fragment: str) -> None:
    assert any(fragment in v for v in violations), violations


@pytest.mark.parametrize(
    "network", sorted(compose_policy.INTERNAL_NETWORKS), ids=lambda n: f"{n}-not-internal"
)
def test_detects_internal_network_made_routable(network: str) -> None:
    raw = _raw_reference()
    raw["networks"][network] = {}
    _assert_detected(compose_policy.check_declared_networks(raw), f"network {network}: must be")

    def mutate(all_: dict[str, Any], _: dict[str, Any]) -> None:
        all_["networks"][network]["internal"] = False

    _assert_detected(_violations_after(mutate), f"network {network}: must be internal")


def test_detects_missing_and_extra_declared_networks() -> None:
    raw = _raw_reference()
    del raw["networks"]["sandbox-net"]
    raw["networks"]["shortcut-net"] = {}
    violations = compose_policy.check_declared_networks(raw)
    _assert_detected(violations, "network sandbox-net: required")
    _assert_detected(violations, "network shortcut-net: not part")


def test_detects_external_network() -> None:
    raw = _raw_reference()
    raw["networks"]["core-net"] = {"internal": True, "external": True}
    _assert_detected(compose_policy.check_declared_networks(raw), "external networks")


@pytest.mark.parametrize("host_ip", [None, "0.0.0.0", "::"], ids=["all-ifaces", "any-v4", "any-v6"])
def test_detects_dashboard_not_loopback_only(host_ip: str | None) -> None:
    def mutate(all_: dict[str, Any], _: dict[str, Any]) -> None:
        port = all_["services"]["dashboard"]["ports"][0]
        if host_ip is None:
            del port["host_ip"]
        else:
            port["host_ip"] = host_ip

    _assert_detected(_violations_after(mutate), "must bind 127.0.0.1 only")


@pytest.mark.parametrize("service", ["db", "gateway-service", "honeypot", "intel-service"])
def test_detects_unexpected_published_port(service: str) -> None:
    def mutate(all_: dict[str, Any], _: dict[str, Any]) -> None:
        all_["services"][service]["ports"] = [
            {"mode": "ingress", "host_ip": "127.0.0.1", "target": 5432, "published": "5432"}
        ]

    _assert_detected(_violations_after(mutate), f"service {service}: publishes port")


@pytest.mark.parametrize(
    "service", ["db", "intel-service", "eval-service", "agent-runtime", "container-api-proxy"]
)
def test_detects_core_service_reachable_from_sandbox(service: str) -> None:
    def mutate(all_: dict[str, Any], _: dict[str, Any]) -> None:
        all_["services"][service]["networks"]["sandbox-net"] = None

    violations = _violations_after(mutate)
    _assert_detected(violations, "would be reachable from agent sandboxes")
    _assert_detected(violations, f"service {service}: networks")


def test_detects_honeypot_on_other_networks() -> None:
    def mutate(all_: dict[str, Any], _: dict[str, Any]) -> None:
        all_["services"]["honeypot"]["networks"]["ingest-net"] = None

    _assert_detected(_violations_after(mutate), "service honeypot: networks")


def test_detects_honeypot_started_by_default() -> None:
    def mutate(all_: dict[str, Any], default: dict[str, Any]) -> None:
        del all_["services"]["honeypot"]["profiles"]
        default["services"]["honeypot"] = all_["services"]["honeypot"]

    violations = _violations_after(mutate)
    _assert_detected(violations, "must be behind a non-default profile")
    _assert_detected(violations, "service honeypot: starts by default")


def test_detects_unexpected_service() -> None:
    def mutate(all_: dict[str, Any], _: dict[str, Any]) -> None:
        all_["services"]["debug-shell"] = _svc("core-net", "sandbox-net")

    violations = _violations_after(mutate)
    _assert_detected(violations, "service debug-shell: not part")


@pytest.mark.parametrize(
    ("key", "value"),
    [("network_mode", "host"), ("privileged", True), ("pid", "host"), ("ipc", "host")],
)
def test_detects_namespace_escapes(key: str, value: Any) -> None:
    def mutate(all_: dict[str, Any], _: dict[str, Any]) -> None:
        all_["services"]["eval-service"][key] = value

    assert any("service eval-service" in v for v in _violations_after(mutate))


def test_detects_runtime_socket_outside_proxy() -> None:
    def mutate(all_: dict[str, Any], _: dict[str, Any]) -> None:
        all_["services"]["agent-runtime"]["volumes"] = [
            {"type": "bind", "source": "/var/run/docker.sock", "target": "/var/run/docker.sock"}
        ]

    _assert_detected(_violations_after(mutate), "agent-runtime: mounts the container-runtime")


def test_detects_honeypot_log_volume_misuse() -> None:
    def writable_shipper(all_: dict[str, Any], _: dict[str, Any]) -> None:
        all_["services"]["log-shipper"]["volumes"][0]["read_only"] = False

    def other_reader(all_: dict[str, Any], _: dict[str, Any]) -> None:
        all_["services"]["intel-service"]["volumes"] = [
            {"type": "volume", "source": "honeypot-logs", "target": "/x", "read_only": True}
        ]

    _assert_detected(_violations_after(writable_shipper), "log-shipper: may not mount")
    _assert_detected(_violations_after(other_reader), "intel-service: may not mount")


@pytest.mark.parametrize("image", ["postgres:16", "postgres:latest", "postgres"])
def test_detects_unpinned_image(image: str) -> None:
    def mutate(all_: dict[str, Any], _: dict[str, Any]) -> None:
        all_["services"]["db"]["image"] = image

    _assert_detected(_violations_after(mutate), "is not pinned by sha256 digest")


@pytest.mark.parametrize("key", ["POSTGRES_PASSWORD", "SERVICE_TOKEN", "LLM_API_KEY"])
def test_detects_inline_secret_environment(key: str) -> None:
    def mutate(all_: dict[str, Any], _: dict[str, Any]) -> None:
        all_["services"]["gateway-service"]["environment"] = {key: "hunter2-literal-value"}

    _assert_detected(_violations_after(mutate), f"secret-like variable {key}")


# --- Deployment job rules (ADR-022) -------------------------------------------------


@pytest.mark.parametrize("network", ["sandbox-net", "core-net", "llm-egress", "operator-net"])
def test_detects_migration_job_on_other_network(network: str) -> None:
    def mutate(all_: dict[str, Any], _: dict[str, Any]) -> None:
        all_["services"]["db-migrate"]["networks"][network] = None

    _assert_detected(_violations_after(mutate), "service db-migrate: networks")


def test_detects_migration_job_reachable_from_sandbox() -> None:
    def mutate(all_: dict[str, Any], _: dict[str, Any]) -> None:
        all_["services"]["db-migrate"]["networks"]["sandbox-net"] = None

    _assert_detected(_violations_after(mutate), "would be reachable from agent sandboxes")


@pytest.mark.parametrize(
    ("key", "value", "fragment"),
    [
        ("ports", [{"target": 8080, "published": "8080", "host_ip": "127.0.0.1"}], "port"),
        ("expose", ["8080"], "must not publish or expose"),
        ("restart", "unless-stopped", "restart must be 'no'"),
        ("restart", "always", "restart must be 'no'"),
        ("read_only", False, "read-only"),
        ("cap_drop", [], "drop all capabilities"),
        ("security_opt", [], "no-new-privileges"),
        ("user", "0:0", "non-root"),
    ],
)
def test_detects_migration_job_hardening_violation(key: str, value: Any, fragment: str) -> None:
    def mutate(all_: dict[str, Any], _: dict[str, Any]) -> None:
        all_["services"]["db-migrate"][key] = value

    _assert_detected(_violations_after(mutate), fragment)


def test_detects_migration_job_started_by_default() -> None:
    def mutate(all_: dict[str, Any], default: dict[str, Any]) -> None:
        del all_["services"]["db-migrate"]["profiles"]
        default["services"]["db-migrate"] = all_["services"]["db-migrate"]

    violations = _violations_after(mutate)
    _assert_detected(violations, "job db-migrate: must be behind a non-default profile")
    _assert_detected(violations, "job db-migrate: starts by default")


@pytest.mark.parametrize("service", ["intel-service", "gateway-service", "agent-runtime"])
def test_detects_runtime_service_on_migrate_net(service: str) -> None:
    def mutate(all_: dict[str, Any], _: dict[str, Any]) -> None:
        all_["services"][service]["networks"]["migrate-net"] = None

    violations = _violations_after(mutate)
    _assert_detected(violations, "could reach the migrator's pg_hba.conf source subnet")
    _assert_detected(violations, f"service {service}: networks")


@pytest.mark.parametrize("service", ["intel-service", "gateway-service", "eval-service"])
def test_detects_runtime_service_given_migration_credential(service: str) -> None:
    def mutate(all_: dict[str, Any], _: dict[str, Any]) -> None:
        all_["services"][service]["secrets"] = [{"source": "aitl_migrator_password"}]

    _assert_detected(_violations_after(mutate), f"service {service}: receives the migration")


@pytest.mark.parametrize("subnet", [None, "10.231.0.0/16", "0.0.0.0/0"])
def test_detects_migrate_net_subnet_drift(subnet: str | None) -> None:
    def mutate(all_: dict[str, Any], _: dict[str, Any]) -> None:
        if subnet is None:
            del all_["networks"]["migrate-net"]["ipam"]
        else:
            all_["networks"]["migrate-net"]["ipam"]["config"][0]["subnet"] = subnet

    _assert_detected(_violations_after(mutate), "network migrate-net: subnet")


# --- P3: honeypot and Log Shipper hardening -------------------------------------------


@pytest.mark.parametrize("service", ["honeypot", "log-shipper"])
@pytest.mark.parametrize(
    ("key", "value", "fragment"),
    [
        ("privileged", True, "privileged containers are forbidden"),
        ("network_mode", "host", "network_mode bypasses"),
        ("pid", "host", "pid=host"),
        ("ipc", "host", "ipc=host"),
        ("read_only", False, "root filesystem must be read-only"),
        ("cap_drop", [], "must drop all capabilities"),
        ("cap_add", ["NET_ADMIN"], "must not add capabilities"),
        ("devices", ["/dev/sda:/dev/sda"], "must not map host devices"),
        ("security_opt", [], "no-new-privileges"),
        ("user", "0:0", "non-root"),
        ("user", None, "non-root"),
        ("mem_limit", None, "mem_limit, cpus and pids_limit are required"),
        ("pids_limit", 100000, "pids_limit"),
        ("cpus", 8.0, "cpus"),
        ("mem_limit", str(8 * 1024**3), "mem_limit"),
        ("tmpfs", ["/scratch"], "must be size-bounded"),
        ("ports", [{"target": 2222, "published": "22", "host_ip": "0.0.0.0"}], "publishes port"),
        (
            "ports",
            [{"target": 2222, "published": "2222", "host_ip": "127.0.0.1"}],
            "publishes port",
        ),
    ],
)
def test_detects_honeypot_side_hardening_regression(
    service: str, key: str, value: Any, fragment: str
) -> None:
    def mutate(all_: dict[str, Any], _: dict[str, Any]) -> None:
        if value is None:
            all_["services"][service].pop(key, None)
        else:
            all_["services"][service][key] = value

    _assert_detected(_violations_after(mutate), fragment)


@pytest.mark.parametrize(
    ("change", "fragment"),
    [
        (lambda h: h.update(environment={"COWRIE_SSH_FORWARDING": "true"}), "no environment"),
        (lambda h: h.update(secrets=[{"source": "ingest_writer_password"}]), "no secret"),
        (lambda h: h.update(depends_on={"db": {}}), "must not depend"),
        (lambda h: h.update(build={"context": "."}), "pinned upstream image"),
        (lambda h: h.update(restart="always"), "restart must be 'no'"),
        (lambda h: h.update(image="cowrie/cowrie:latest"), "not pinned by sha256"),
        (
            lambda h: h["volumes"].append(
                {"type": "bind", "source": "/var/run/docker.sock", "target": "/var/run/docker.sock"}
            ),
            "mounts the container-runtime socket",
        ),
        (
            lambda h: h["volumes"].append({"type": "bind", "source": "/", "target": "/host"}),
            "unexpected bind mount",
        ),
        (
            lambda h: h["volumes"].append({"type": "volume", "source": "db-data", "target": "/x"}),
            "unexpected volume",
        ),
        (lambda h: h["volumes"][0].update(read_only=False), "is not allowed"),
        (lambda h: h["volumes"].pop(1), "required mount"),
        (lambda h: h.update(tmpfs=["/cowrie/cowrie-git/var/lib/cowrie:size=64m"]), "bounded tmpfs"),
        (lambda h: h["networks"].update({"ingest-net": None}), "service honeypot: networks"),
        (lambda h: h["networks"].update({"core-net": None}), "service honeypot: networks"),
        (lambda h: h["networks"].update({"migrate-net": None}), "service honeypot: networks"),
        (lambda h: h["networks"].update({"sandbox-net": None}), "reachable from agent sandboxes"),
        (lambda h: h["networks"].update({"llm-egress": None}), "service honeypot: networks"),
    ],
)
def test_detects_honeypot_specific_regression(change: Any, fragment: str) -> None:
    def mutate(all_: dict[str, Any], _: dict[str, Any]) -> None:
        change(all_["services"]["honeypot"])

    _assert_detected(_violations_after(mutate), fragment)


def test_detects_unbounded_honeypot_log_volume() -> None:
    def mutate(all_: dict[str, Any], _: dict[str, Any]) -> None:
        all_["volumes"]["honeypot-logs"] = {"driver": "local"}

    _assert_detected(_violations_after(mutate), "must be size-bounded")


def test_real_compose_honeypot_covers_image_volumes(rendered_all: dict[str, Any]) -> None:
    honeypot = rendered_all["services"]["honeypot"]
    targets = {m["target"] for m in honeypot["volumes"]} | {
        t.split(":", 1)[0] for t in honeypot["tmpfs"]
    }
    assert {compose_policy.COWRIE_ETC, compose_policy.COWRIE_VAR} <= targets
    assert honeypot["user"] == "999:999"
    assert "COWRIE" not in json.dumps(honeypot.get("environment") or {})
