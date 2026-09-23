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
    "db": frozenset({"core-net", "ingest-net", "migrate-net"}),
    "intel-service": frozenset({"core-net"}),
    "agent-runtime": frozenset({"core-net", "orchestration-net"}),
    "gateway-service": frozenset({"core-net", "sandbox-net", "llm-egress"}),
    "eval-service": frozenset({"core-net"}),
    "dashboard": frozenset({"core-net", "operator-net"}),
    "container-api-proxy": frozenset({"orchestration-net"}),
}

# Ephemeral deployment jobs (ADR-022): not runtime services. Each runs once via
# `docker compose run --rm`, behind a non-default profile, and exits.
EXPECTED_JOB_NETWORKS: Mapping[str, frozenset[str]] = {
    "db-migrate": frozenset({"migrate-net"}),
}

INTERNAL_NETWORKS = frozenset(
    {"honeypot-net", "ingest-net", "core-net", "sandbox-net", "orchestration-net", "migrate-net"}
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

# migrate-net carries only db <-> db-migrate; pg_hba.conf admits aitl_migrator only
# from this subnet, so the subnet must be fixed and match (ADR-022).
MIGRATE_NET = "migrate-net"
MIGRATE_NET_SUBNET = "10.231.254.0/29"
MIGRATE_NET_MEMBERS = frozenset({"db", "db-migrate"})
# Only the db (to create the role) and the migration job may receive the migrator
# credential; the owner has no credential at all (ADR-022).
MIGRATOR_SECRET = "aitl_migrator_password"  # noqa: S105 - a secret name, not a value
MIGRATOR_SECRET_HOLDERS = frozenset({"db", "db-migrate"})

# P3 hardening (FR-004a, FR-004b, FR-017-style limits): per-service ceilings for
# (memory bytes, cpus, pids). A hardened service must declare all three.
RESOURCE_CEILINGS: Mapping[str, tuple[int, float, int]] = {
    "honeypot": (512 * 1024 * 1024, 1.0, 256),
    "log-shipper": (256 * 1024 * 1024, 0.5, 64),
}
# Cowrie 3.0.15 image layout (docker/Dockerfile of the release): the image
# declares these VOLUMEs, which must be covered explicitly or they become
# writable, unbounded anonymous volumes under a read-only root.
COWRIE_ETC = "/cowrie/cowrie-git/etc"
COWRIE_VAR = "/cowrie/cowrie-git/var"
COWRIE_LOG_DIR = "/cowrie/cowrie-git/var/log/cowrie"
COWRIE_CONFIG_SOURCE_SUFFIX = "/honeypot/cowrie/etc"

# Log Shipper (ARCHITECTURE.md §9; PRD FR-004b, FR-004d, FR-005b). In the
# single-host profile it runs fixture mode only: the synthetic corpus read-only,
# never the honeypot volume (live mode belongs to the honeypot-host profile).
SHIPPER = "log-shipper"
SHIPPER_SOURCE = "/srv/aitl/source"
SHIPPER_STATE = "/srv/aitl/state"
SHIPPER_STATE_VOLUME = "shipper-state"
SHIPPER_CORPUS_SUFFIX = "/corpus/honeypot_sessions_v1"
INGEST_SECRET = "ingest_writer_password"  # noqa: S105 - a secret name, not a value
INGEST_SECRET_HOLDERS = frozenset({"db", SHIPPER})
SHIPPER_REQUIRED_ENV: Mapping[str, str] = {
    "SHIPPER_MODE": "fixture",
    "SHIPPER_SOURCE_DIR": SHIPPER_SOURCE,
    "SHIPPER_STATE_DIR": SHIPPER_STATE,
    "AITL_DB_HOST": "db",
    "AITL_DB_USER": "ingest_writer",
    "AITL_DB_PASSWORD_FILE": f"/run/secrets/{INGEST_SECRET}",
}

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

    migrate = networks.get(MIGRATE_NET) or {}
    subnets = [c.get("subnet") for c in (migrate.get("ipam") or {}).get("config") or []]
    if MIGRATE_NET in networks and subnets != [MIGRATE_NET_SUBNET]:
        violations.append(
            f"network {MIGRATE_NET}: subnet {subnets} != {MIGRATE_NET_SUBNET} (pg_hba.conf)"
        )

    sandbox_net_members: set[str] = set()
    for name, service in services.items():
        expected = EXPECTED_SERVICE_NETWORKS.get(name) or EXPECTED_JOB_NETWORKS.get(name)
        if expected is None:
            violations.append(f"service {name}: not part of the ARCHITECTURE.md §28 topology")
            continue
        if name in EXPECTED_JOB_NETWORKS:
            violations.extend(_check_deployment_job(name, service, default_services))
        secrets = {str(s.get("source")) for s in service.get("secrets") or []}
        if MIGRATOR_SECRET in secrets and name not in MIGRATOR_SECRET_HOLDERS:
            violations.append(f"service {name}: receives the migration credential")
        if INGEST_SECRET in secrets and name not in INGEST_SECRET_HOLDERS:
            violations.append(f"service {name}: receives the ingest_writer credential")

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
            if source == SHIPPER_STATE_VOLUME and name != SHIPPER:
                violations.append(f"service {name}: may not mount {SHIPPER_STATE_VOLUME}")
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

        if name in RESOURCE_CEILINGS:
            violations.extend(_check_hardened(name, service))
        if name == "honeypot":
            violations.extend(_check_honeypot(service))
        if name == SHIPPER:
            violations.extend(_check_log_shipper(service))

        environment = service.get("environment") or {}
        for key, value in environment.items():
            secret_like = _SECRET_ENV_NAME.search(key.upper()) and not key.upper().endswith("_FILE")
            if secret_like and value not in (None, ""):
                violations.append(
                    f"service {name}: secret-like variable {key} set inline (use a *_FILE secret)"
                )

    log_volume = (rendered_all_profiles.get("volumes") or {}).get(HONEYPOT_LOG_VOLUME)
    if log_volume is not None:
        options = str(((log_volume or {}).get("driver_opts") or {}).get("o", ""))
        if "size=" not in options:
            violations.append(f"volume {HONEYPOT_LOG_VOLUME}: must be size-bounded")

    migrate_members = {
        name for name, svc in services.items() if MIGRATE_NET in (svc.get("networks") or {})
    }
    if migrate_members - MIGRATE_NET_MEMBERS:
        violations.append(
            f"{MIGRATE_NET}: {sorted(migrate_members - MIGRATE_NET_MEMBERS)} could reach the "
            "migrator's pg_hba.conf source subnet"
        )

    unexpected_peers = sandbox_net_members - SANDBOX_NET_PEERS
    if unexpected_peers:
        violations.append(
            f"sandbox-net: {sorted(unexpected_peers)} would be reachable from agent sandboxes"
        )
    return violations


def _check_deployment_job(
    name: str, service: Mapping[str, Any], default_services: set[str]
) -> list[str]:
    """ADR-022: a deployment job is ephemeral, never a long-running or listening service."""
    violations: list[str] = []
    if not service.get("profiles"):
        violations.append(f"job {name}: must be behind a non-default profile")
    if name in default_services:
        violations.append(f"job {name}: starts by default (must run only via `run --rm`)")
    if service.get("restart", "no") != "no":
        violations.append(f"job {name}: restart must be 'no' (a job may not stay running)")
    if service.get("ports") or service.get("expose"):
        violations.append(f"job {name}: must not publish or expose any port")
    if service.get("read_only") is not True:
        violations.append(f"job {name}: root filesystem must be read-only")
    if "ALL" not in (service.get("cap_drop") or []):
        violations.append(f"job {name}: must drop all capabilities")
    if "no-new-privileges:true" not in (service.get("security_opt") or []):
        violations.append(f"job {name}: must set no-new-privileges")
    user = str(service.get("user") or "")
    if user.split(":")[0] in ("", "0", "root"):
        violations.append(f"job {name}: must run as a non-root user")
    return violations


def _check_hardened(name: str, service: Mapping[str, Any]) -> list[str]:
    """Container hardening for the honeypot side (ARCHITECTURE.md §9)."""
    violations: list[str] = []
    if service.get("read_only") is not True:
        violations.append(f"service {name}: root filesystem must be read-only")
    if "ALL" not in (service.get("cap_drop") or []):
        violations.append(f"service {name}: must drop all capabilities")
    if service.get("cap_add"):
        violations.append(f"service {name}: must not add capabilities")
    if service.get("devices"):
        violations.append(f"service {name}: must not map host devices")
    if "no-new-privileges:true" not in (service.get("security_opt") or []):
        violations.append(f"service {name}: must set no-new-privileges")
    user = str(service.get("user") or "")
    if user.split(":")[0] in ("", "0", "root"):
        violations.append(f"service {name}: must run as a non-root user")
    max_mem, max_cpus, max_pids = RESOURCE_CEILINGS[name]
    try:
        mem = int(str(service.get("mem_limit")))
        cpus = float(str(service.get("cpus")))
        pids = int(str(service.get("pids_limit")))
    except ValueError:
        return [*violations, f"service {name}: mem_limit, cpus and pids_limit are required"]
    if not 0 < mem <= max_mem:
        violations.append(f"service {name}: mem_limit {mem} exceeds {max_mem}")
    if not 0 < cpus <= max_cpus:
        violations.append(f"service {name}: cpus {cpus} exceeds {max_cpus}")
    if not 0 < pids <= max_pids:
        violations.append(f"service {name}: pids_limit {pids} exceeds {max_pids}")
    for entry in service.get("tmpfs") or []:
        if "size=" not in str(entry):
            violations.append(f"service {name}: tmpfs {entry!r} must be size-bounded")
    return violations


def _check_honeypot(service: Mapping[str, Any]) -> list[str]:
    """The honeypot holds nothing and can reach nothing but its own log volume."""
    violations: list[str] = []
    if service.get("environment"):
        # Cowrie treats COWRIE_<SECTION>_<OPTION> variables as config overrides.
        violations.append("service honeypot: must set no environment (COWRIE_* overrides config)")
    if service.get("secrets"):
        violations.append("service honeypot: must hold no secret")
    if service.get("depends_on"):
        violations.append("service honeypot: must not depend on any other service")
    if service.get("build"):
        violations.append("service honeypot: must run the pinned upstream image, not a build")
    if service.get("restart", "no") != "no":
        violations.append("service honeypot: restart must be 'no' in the isolation profile")
    allowed = {
        ("bind", COWRIE_ETC, True),
        ("volume", COWRIE_LOG_DIR, False),
    }
    mounts = set()
    for mount in _volume_mounts(service):
        kind = str(mount.get("type"))
        target = str(mount.get("target"))
        read_only = mount.get("read_only") is True
        mounts.add((kind, target, read_only))
        if kind == "bind" and not str(mount.get("source", "")).endswith(
            COWRIE_CONFIG_SOURCE_SUFFIX
        ):
            violations.append(f"service honeypot: unexpected bind mount {mount.get('source')}")
        if kind == "volume" and mount.get("source") != HONEYPOT_LOG_VOLUME:
            violations.append(f"service honeypot: unexpected volume {mount.get('source')}")
    for extra in sorted(mounts - allowed):
        violations.append(f"service honeypot: mount {extra} is not allowed")
    for missing in sorted(allowed - mounts):
        violations.append(f"service honeypot: required mount {missing} is missing")
    tmpfs_targets = {str(entry).split(":", 1)[0] for entry in service.get("tmpfs") or []}
    if COWRIE_VAR not in tmpfs_targets:
        violations.append(f"service honeypot: {COWRIE_VAR} must be a bounded tmpfs")
    return violations


def _check_log_shipper(service: Mapping[str, Any]) -> list[str]:
    """Portless, INSERT-only, read-only source, fixture mode in this profile."""
    violations: list[str] = []
    if service.get("ports") or service.get("expose"):
        violations.append("service log-shipper: must not publish or expose any port")
    if service.get("profiles"):
        violations.append("service log-shipper: must run in the default profile")
    secrets = sorted(str(s.get("source")) for s in service.get("secrets") or [])
    if secrets != [INGEST_SECRET]:
        violations.append(f"service log-shipper: secrets {secrets} != [{INGEST_SECRET!r}]")
    environment = service.get("environment") or {}
    for key, expected in SHIPPER_REQUIRED_ENV.items():
        if environment.get(key) != expected:
            violations.append(
                f"service log-shipper: {key}={environment.get(key)!r} (expected {expected!r})"
            )
    if "honeypot" in (service.get("depends_on") or {}):
        violations.append("service log-shipper: must not depend on the honeypot")
    if not (service.get("healthcheck") or {}).get("test"):
        violations.append("service log-shipper: must declare a health check")
    allowed = {
        ("bind", SHIPPER_SOURCE, True),
        ("volume", SHIPPER_STATE, False),
    }
    mounts = set()
    for mount in _volume_mounts(service):
        kind = str(mount.get("type"))
        mounts.add((kind, str(mount.get("target")), mount.get("read_only") is True))
        source = str(mount.get("source", ""))
        if kind == "bind" and not source.endswith(SHIPPER_CORPUS_SUFFIX):
            violations.append(f"service log-shipper: unexpected bind mount {source}")
        if kind == "volume" and source != SHIPPER_STATE_VOLUME:
            violations.append(f"service log-shipper: unexpected volume {source}")
    for extra in sorted(mounts - allowed):
        violations.append(f"service log-shipper: mount {extra} is not allowed")
    for missing in sorted(allowed - mounts):
        violations.append(f"service log-shipper: required mount {missing} is missing")
    return violations
