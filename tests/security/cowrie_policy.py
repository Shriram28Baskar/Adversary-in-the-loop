"""Checker for the Cowrie configuration against PRD FR-004a and ARCHITECTURE.md §9.

The effective configuration is what Cowrie 3.0.15 computes: its bundled
``cowrie.cfg.dist`` (vendored under ``tests/security/data/cowrie-3.0.15``)
overlaid by ``honeypot/cowrie/etc/cowrie.cfg``. Checks return human-readable
violations; an empty list means compliant.
"""

from __future__ import annotations

import configparser
import re
from pathlib import Path
from typing import Final

REPO_ROOT = Path(__file__).resolve().parents[2]
DIST = REPO_ROOT / "tests" / "security" / "data" / "cowrie-3.0.15" / "cowrie.cfg.dist"
OVERLAY = REPO_ROOT / "honeypot" / "cowrie" / "etc" / "cowrie.cfg"
USERDB = REPO_ROOT / "honeypot" / "cowrie" / "etc" / "userdb.txt"
# sha256 of the vendored default configuration of the pinned release.
DIST_SHA256: Final = "efe23c4327d1e32b7b331cb440fe6fdeda171463b757a39ec5b520742578a99b"

# (section, option) -> required effective value. Each is also required to be
# set explicitly in the overlay, never left to a default.
REQUIRED: Final[dict[tuple[str, str], str]] = {
    # No direct-tcpip / port forwarding (FR-004a).
    ("ssh", "forwarding"): "false",
    ("ssh", "forward_redirect"): "false",
    ("ssh", "forward_tunnel"): "false",
    ("telnet", "enabled"): "false",
    # In-process emulation only: no proxy/pool backend (real VMs), no LLM backend.
    ("honeypot", "backend"): "shell",
    ("honeypot", "auth_class"): "UserDB",
    # Download/fetch emulation fails: outbound sockets bind to loopback.
    ("honeypot", "out_addr"): "127.0.0.1",
    ("honeypot", "download_limit_size"): "1",
    ("honeypot", "ttylog"): "false",
    ("honeypot", "log_path"): "var/log/cowrie",
    ("output_jsonlog", "enabled"): "true",
    ("output_jsonlog", "logfile"): "${honeypot:log_path}/cowrie.json",
    ("output_jsonlog", "epoch_timestamp"): "false",
    ("ssh", "listen_endpoints"): "tcp:2222:interface=0.0.0.0",
}
ONLY_OUTPUT: Final = "output_jsonlog"
_COMMENTED_KEY = re.compile(r"^#\s*([a-z_][a-z0-9_]*)\s*=", re.MULTILINE)


def _parser() -> configparser.ConfigParser:
    return configparser.ConfigParser(interpolation=None, strict=True)


def read_effective(dist_text: str, overlay_text: str) -> configparser.ConfigParser:
    parser = _parser()
    parser.read_string(dist_text, source="cowrie.cfg.dist")
    parser.read_string(overlay_text, source="cowrie.cfg")
    return parser


def documented_keys(dist_text: str) -> dict[str, set[str]]:
    """Keys the release knows per section: active keys plus commented examples."""
    keys: dict[str, set[str]] = {}
    section = None
    for line in dist_text.splitlines():
        header = re.match(r"^\[([^\]]+)\]\s*$", line)
        if header:
            section = header.group(1)
            keys.setdefault(section, set())
            continue
        if section is None:
            continue
        active = re.match(r"^([a-z_][a-z0-9_]*)\s*=", line)
        commented = _COMMENTED_KEY.match(line)
        if active:
            keys[section].add(active.group(1))
        elif commented:
            keys[section].add(commented.group(1))
    return keys


def check(dist_text: str, overlay_text: str) -> list[str]:
    violations: list[str] = []
    try:
        overlay = _parser()
        overlay.read_string(overlay_text, source="cowrie.cfg")
        effective = read_effective(dist_text, overlay_text)
    except configparser.Error as exc:
        return [f"configuration does not parse strictly: {exc}"]

    known = documented_keys(dist_text)
    for section in overlay.sections():
        if section not in known:
            violations.append(f"[{section}] is not a section of the pinned release")
            continue
        for option in overlay[section]:
            if option not in known[section]:
                violations.append(
                    f"[{section}] {option} is not an option of the pinned release "
                    "(Cowrie ignores unknown keys, so a typo would leave the default)"
                )

    for (section, option), value in REQUIRED.items():
        if not overlay.has_option(section, option):
            violations.append(f"[{section}] {option} must be set explicitly in the overlay")
        actual = effective.get(section, option, fallback=None)
        if actual != value:
            violations.append(f"[{section}] {option} = {actual!r}, required {value!r}")

    for section in effective.sections():
        if section.startswith("output_") and section != ONLY_OUTPUT:
            enabled = effective.get(section, "enabled", fallback="false").strip().lower()
            if enabled not in ("false", "no", "off", "0"):
                violations.append(f"[{section}] must stay disabled (only {ONLY_OUTPUT} is allowed)")
            if not overlay.has_option(section, "enabled"):
                violations.append(f"[{section}] enabled must be set explicitly to false")
    return violations


_USERDB_LINE = re.compile(r"^[a-z][a-z0-9_-]{0,31}:x:(?:\*|!?[A-Za-z0-9_.-]{1,32})$")


def check_userdb(text: str) -> list[str]:
    violations = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        if not _USERDB_LINE.match(line):
            violations.append(f"userdb line {number} is not a simple user:x:password entry")
    return violations
