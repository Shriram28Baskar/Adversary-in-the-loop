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
    assert "POSTGRES_IMAGE" in result.stderr


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


def _reference() -> tuple[dict[str, Any], dict[str, Any]]:
    """The full ARCHITECTURE.md §28 single-host topology in rendered form."""
    networks = {
        name: {"name": f"aitl_{name}", "internal": name in compose_policy.INTERNAL_NETWORKS}
        for name in compose_policy.DECLARED_NETWORKS
    }
    services = {
        "honeypot": _svc(
            "honeypot-net",
            profiles=["honeypot-isolation"],
            volumes=[{"type": "volume", "source": "honeypot-logs", "target": "/logs"}],
        ),
        "log-shipper": _svc(
            "ingest-net",
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
        "db": _svc("core-net", "ingest-net"),
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
    }
    rendered_all = {"services": services, "networks": networks}
    rendered_default = {
        "services": {k: v for k, v in services.items() if k != "honeypot"},
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
