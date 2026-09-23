"""Cowrie fetch/download restriction is independent of zero egress (PRD FR-004a; ADR-023).

Cowrie 3.0.15 has no switch that removes its wget/curl/tftp/ftpget/nc
emulation. FR-004a therefore relies on two independent controls:

1. **Application restriction** (this file): every outbound fetch path in the
   pinned release binds its socket to ``[honeypot] out_addr`` (committed as
   ``127.0.0.1``), refuses non-globally-routable targets, and aborts transfers
   over ``download_limit_size`` (committed as ``1``). Proven from the vendored
   upstream sources (sha256-pinned) plus the committed configuration.
2. **Network zero egress** (``test_runtime_isolation.py``): the honeypot's
   network namespace has no route out at all.

Independence: each control's checker passes or fails regardless of the other
(the mutation tests below). The runtime proof that removing network isolation
still leaves fetches non-functional (a loopback-bound socket on an open
network fails with EINVAL) is ``test_loopback_bound_fetch_fails_on_an_open_network``
in ``test_runtime_isolation.py``.
"""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from tests.security import compose_policy, cowrie_policy

UPSTREAM = Path(__file__).resolve().parent / "data" / "cowrie-3.0.15" / "src" / "cowrie"
# sha256 of each vendored upstream file (cowrie-3.0.15.tar.gz from PyPI, see SOURCE.md).
UPSTREAM_SHA256 = {
    "commands/curl.py.txt": "d626723c692da2ff25e23d870d8d6ed5044bf36e6427b0bdbe5c57e1f1da740a",
    "commands/ftpget.py.txt": "04d9c840b067da0d65098aaccba35a7380c8b74275148a9806650b2d9aa46492",
    "commands/nc.py.txt": "6a007c1cdb35a876adb8b42c7567528e2f7cec8bc5a65f55a1e7e908b541e6a2",
    "commands/tftp.py.txt": "797301b9fbe22bda2fee3bd1c2ee5127042f047ce3e0f1535b7f11cf75d2867a",
    "commands/wget.py.txt": "6aaae2cac75a6d8a131de63c087f9b5eeb3731f9146b9d4480bb3e79924af060",
    "core/download.py.txt": "e110828bb893fc8db3f13c0186a5cfbca06ee880d9156f95ba40949517ee443c",
    "core/network.py.txt": "fee94f0f12074ad50e77f3169ac7eea799eed75978c411013344b320fe5a6c17",
}
LIMIT = 'CowrieConfig.getint("honeypot", "download_limit_size", fallback=0)'
BIND = "bindAddress=(outbound_bind_address(), 0)"
# Per fetch command: the upstream code that applies each restriction.
FETCH_PATHS: dict[str, dict[str, str]] = {
    "wget": {"gate": "communication_allowed(self.host)", "bind": BIND, "limit": LIMIT},
    # curl connects through core.download.fetch (pinned_agent binds, fetch gates).
    "curl": {"gate": "communication_allowed(self.host)", "bind": "fetch(", "limit": LIMIT},
    "tftp": {
        "gate": "communication_allowed(self.host_ip)",
        "bind": "interface=outbound_bind_address()",
        "limit": 'CowrieConfig.getint("honeypot", "download_limit_size", fallback=0)',
    },
    "ftpget": {"gate": "resolve_allowed(self.host)", "bind": BIND, "limit": LIMIT},
    "nc": {"gate": "resolve_allowed(host)", "bind": BIND, "limit": LIMIT},
}
REPO_ROOT = Path(__file__).resolve().parents[2]


def _upstream(name: str) -> str:
    return (UPSTREAM / name).read_text(encoding="utf-8")


def test_vendored_upstream_sources_are_the_pinned_release() -> None:
    found = {str(p.relative_to(UPSTREAM)) for p in UPSTREAM.rglob("*.txt")}
    assert found == set(UPSTREAM_SHA256)
    for name, digest in UPSTREAM_SHA256.items():
        assert hashlib.sha256((UPSTREAM / name).read_bytes()).hexdigest() == digest, name


@pytest.mark.parametrize("command", sorted(FETCH_PATHS))
def test_every_fetch_path_applies_the_application_restrictions(command: str) -> None:
    source = _upstream(f"commands/{command}.py.txt")
    for control, evidence in FETCH_PATHS[command].items():
        assert evidence in source, (command, control)


def test_shared_fetch_helpers_bind_gate_and_block_non_global_targets() -> None:
    network = _upstream("core/network.py.txt")
    assert 'return CowrieConfig.get("honeypot", "out_addr", fallback="0.0.0.0")' in network
    assert "if not candidate.is_global:\n            return True" in network
    assert "if _is_blocked(ip):\n        return None" in network
    download = _upstream("core/download.py.txt")
    assert BIND in download
    assert "address = yield resolve_allowed(host)" in download


def _effective() -> Any:
    return cowrie_policy.read_effective(
        cowrie_policy.DIST.read_text(encoding="utf-8"),
        cowrie_policy.OVERLAY.read_text(encoding="utf-8"),
    )


def _assert_application_restriction() -> None:
    config = _effective()
    out_addr = ipaddress.ip_address(config.get("honeypot", "out_addr"))
    assert out_addr.is_loopback
    limit = config.getint("honeypot", "download_limit_size")
    assert 0 < limit <= 1  # 0 would mean "unlimited" upstream
    assert config.getboolean("ssh", "forwarding") is False


def test_committed_config_restricts_fetch_at_the_application_layer() -> None:
    """(1) Fetch is application-restricted: loopback source, 1-byte cap."""
    _assert_application_restriction()


# --- (3) independence of the two controls ----------------------------------------------


def _render_compose() -> dict[str, Any]:
    result = subprocess.run(
        [
            "docker", "compose",
            "--env-file", str(REPO_ROOT / "deploy" / "versions.env"),
            "-f", str(REPO_ROOT / "docker-compose.yml"),
            "--profile", "*", "config", "--format", "json",
        ],
        capture_output=True, text=True, check=True, cwd=REPO_ROOT,
    )  # fmt: skip
    rendered: dict[str, Any] = json.loads(result.stdout)
    return rendered


def _compose_violations(rendered: dict[str, Any]) -> list[str]:
    default = copy.deepcopy(rendered)
    default["services"] = {k: v for k, v in rendered["services"].items() if not v.get("profiles")}
    return compose_policy.check_services(rendered, default)


def test_weakened_network_leaves_the_application_restriction_intact() -> None:
    """Removing network isolation is caught by the network check alone; the
    application restriction still holds, so fetch is not unrestricted."""
    rendered = _render_compose()
    assert _compose_violations(rendered) == []
    weakened = copy.deepcopy(rendered)
    weakened["networks"]["honeypot-net"]["internal"] = False
    weakened["services"]["honeypot"]["networks"]["core-net"] = None
    assert _compose_violations(weakened) != []
    # The application-layer control is evaluated from Cowrie's config only.
    assert (
        cowrie_policy.check(
            cowrie_policy.DIST.read_text(encoding="utf-8"),
            cowrie_policy.OVERLAY.read_text(encoding="utf-8"),
        )
        == []
    )
    _assert_application_restriction()


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("out_addr = 127.0.0.1", "out_addr = 0.0.0.0"),
        ("download_limit_size = 1", "download_limit_size = 0"),
    ],
)
def test_weakened_application_restriction_leaves_zero_egress_intact(old: str, new: str) -> None:
    overlay = cowrie_policy.OVERLAY.read_text(encoding="utf-8")
    assert old in overlay
    weakened = overlay.replace(old, new)
    assert cowrie_policy.check(cowrie_policy.DIST.read_text(encoding="utf-8"), weakened) != []
    # The network boundary is evaluated from Compose only and is unaffected.
    assert _compose_violations(_render_compose()) == []
