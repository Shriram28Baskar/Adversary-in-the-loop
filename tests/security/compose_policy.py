"""Checker for the single-host Compose topology against ARCHITECTURE.md §28.

The expected topology below is transcribed from ARCHITECTURE.md §28 (network
membership table), §9 (one-way honeypot log volume), §31 (single-host
profile), ADR-010 (no internet-exposed honeypot in this profile), and ADR-019
(only the container API proxy touches the container-runtime socket).

Checks operate on ``docker compose config --format json`` output (the
normalized form Compose itself uses) and on the raw YAML network declarations,
because rendered output omits networks no service uses yet. Each check returns
a list of human-readable violations; an empty list means compliant.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

# ARCHITECTURE.md §28: exact network membership per Compose service.
EXPECTED_SERVICE_NETWORKS: Mapping[str, frozenset[str]] = {
    "honeypot": frozenset({"honeypot-net"}),
    "log-shipper": frozenset({"ingest-net"}),
    "db": frozenset({"core-net", "ingest-net"}),
    "intel-service": frozenset({"core-net"}),
    "agent-runtime": frozenset({"core-net", "orchestration-net"}),
    "gateway-service": frozenset({"core-net", "sandbox-net", "llm-egress"}),
    "eval-service": frozenset({"core-net"}),
    "dashboard": frozenset({"core-net", "operator-net"}),
    "container-api-proxy": frozenset({"orchestration-net"}),
}

INTERNAL_NETWORKS = frozenset(
    {"honeypot-net", "ingest-net", "core-net", "sandbox-net", "orchestration-net"}
)
OUTBOUND_NETWORKS = frozenset({"llm-egress", "operator-net"})
DECLARED_NETWORKS = INTERNAL_NETWORKS | OUTBOUND_NETWORKS

# Only gateway-service may share sandbox-net with the per-execution sandbox (ADR-011).
SANDBOX_NET_PEERS = frozenset({"gateway-service"})
# Only the dashboard publishes a port, and only on loopback (ARCHITECTURE.md §23, §31).
PUBLISHERS = frozenset({"dashboard"})
LOOPBACK = "127.0.0.1"
# Services that must never start by default in the single-host profile (FR-004d).
PROFILE_ONLY = frozenset({"honeypot"})
# Only the container API proxy may mount the container-runtime socket (ADR-019).
RUNTIME_SOCKET_ALLOWED = frozenset({"container-api-proxy"})
# One-way honeypot log volume (ARCHITECTURE.md §9, ADR-009).
HONEYPOT_LOG_VOLUME = "honeypot-logs"
HONEYPOT_LOG_WRITERS = frozenset({"honeypot"})
HONEYPOT_LOG_READONLY_READERS = frozenset({"log-shipper"})

_DIGEST_PINNED = re.compile(r"@sha256:[0-9a-f]{64}$")
_SECRET_ENV_NAME = re.compile(r"(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|CREDENTIAL)")


def check_declared_networks(raw_compose: Mapping[str, Any]) -> list[str]:
    """Every §28 network is declared, with the right ``internal`` flag, and nothing else."""
    violations: list[str] = []
    declared = raw_compose.get("networks") or {}
    for name in sorted(set(declared) - DECLARED_NETWORKS):
        violations.append(f"network {name}: not part of the ARCHITECTURE.md §28 topology")
    for name in sorted(DECLARED_NETWORKS - set(declared)):
        violations.append(f"network {name}: required by ARCHITECTURE.md §28 but not declared")
    for name in sorted(set(declared) & DECLARED_NETWORKS):
        spec = declared[name] or {}
        if spec.get("external"):
            violations.append(f"network {name}: external networks cannot be verified")
        if spec.get("driver") == "host":
            violations.append(f"network {name}: host driver is forbidden")
        internal = spec.get("internal") is True
        if name in INTERNAL_NETWORKS and not internal:
            violations.append(f"network {name}: must be internal (no external egress)")
        if name in OUTBOUND_NETWORKS and internal:
            violations.append(f"network {name}: must allow outbound for its single member")
    return violations


def _published_ports(service: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return [port for port in service.get("ports") or [] if port.get("published")]


def _volume_mounts(service: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return [mount for mount in service.get("volumes") or [] if isinstance(mount, Mapping)]


def check_services(
    rendered_all_profiles: Mapping[str, Any], rendered_default: Mapping[str, Any]
) -> list[str]:
    """Check every service (including profiled ones) against §28 and related ADRs."""
    violations: list[str] = []
    services: Mapping[str, Any] = rendered_all_profiles.get("services") or {}
    default_services = set((rendered_default.get("services") or {}).keys())
    networks: Mapping[str, Any] = rendered_all_profiles.get("networks") or {}

    for name, network in networks.items():
        if name not in DECLARED_NETWORKS:
            violations.append(f"network {name}: not part of the ARCHITECTURE.md §28 topology")
            continue
        if name in INTERNAL_NETWORKS and network.get("internal") is not True:
            violations.append(f"network {name}: must be internal (no external egress)")
        if network.get("external"):
            violations.append(f"network {name}: external networks cannot be verified")

    sandbox_net_members: set[str] = set()
    for name, service in services.items():
        expected = EXPECTED_SERVICE_NETWORKS.get(name)
        if expected is None:
            violations.append(f"service {name}: not part of the ARCHITECTURE.md §28 topology")
            continue

        if "network_mode" in service:
            violations.append(f"service {name}: network_mode bypasses the network topology")
        attached = frozenset((service.get("networks") or {}).keys())
        if attached != expected:
            violations.append(
                f"service {name}: networks {sorted(attached)} != expected {sorted(expected)}"
            )
        if "sandbox-net" in attached:
            sandbox_net_members.add(name)

        if service.get("privileged"):
            violations.append(f"service {name}: privileged containers are forbidden")
        for namespace in ("pid", "ipc", "uts", "userns_mode"):
            if service.get(namespace) == "host":
                violations.append(f"service {name}: {namespace}=host is forbidden")

        for port in _published_ports(service):
            if name not in PUBLISHERS:
                violations.append(
                    f"service {name}: publishes port {port.get('published')} "
                    "(only the dashboard may publish)"
                )
            elif port.get("host_ip") != LOOPBACK:
                violations.append(
                    f"service {name}: port {port.get('published')} must bind {LOOPBACK} only"
                )

        if name in PROFILE_ONLY:
            if not service.get("profiles"):
                violations.append(f"service {name}: must be behind a non-default profile")
            if name in default_services:
                violations.append(f"service {name}: starts by default")

        for mount in _volume_mounts(service):
            source = str(mount.get("source", ""))
            target = str(mount.get("target", ""))
            if ("docker.sock" in source or "docker.sock" in target) and (
                name not in RUNTIME_SOCKET_ALLOWED
            ):
                violations.append(f"service {name}: mounts the container-runtime socket")
            if source == HONEYPOT_LOG_VOLUME:
                read_only = mount.get("read_only") is True
                if name in HONEYPOT_LOG_WRITERS:
                    continue
                if name in HONEYPOT_LOG_READONLY_READERS and read_only:
                    continue
                violations.append(
                    f"service {name}: may not mount {HONEYPOT_LOG_VOLUME}"
                    + ("" if name not in HONEYPOT_LOG_READONLY_READERS else " read-write")
                )

        image = service.get("image")
        if image is not None and not _DIGEST_PINNED.search(str(image)):
            violations.append(f"service {name}: image {image!r} is not pinned by sha256 digest")

        environment = service.get("environment") or {}
        for key, value in environment.items():
            secret_like = _SECRET_ENV_NAME.search(key.upper()) and not key.upper().endswith("_FILE")
            if secret_like and value not in (None, ""):
                violations.append(
                    f"service {name}: secret-like variable {key} set inline (use a *_FILE secret)"
                )

    unexpected_peers = sandbox_net_members - SANDBOX_NET_PEERS
    if unexpected_peers:
        violations.append(
            f"sandbox-net: {sorted(unexpected_peers)} would be reachable from agent sandboxes"
        )
    return violations
