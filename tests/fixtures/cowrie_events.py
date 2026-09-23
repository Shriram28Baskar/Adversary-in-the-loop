"""Cowrie-shaped test lines, built as JSON and accepted through the real parser (P4 tests)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aitl_common.config.bundle import load_config
from aitl_common.config.schemas.intel import PhaseRules
from aitl_common.telemetry.cowrie import Accepted, parse_line

REPO_ROOT = Path(__file__).resolve().parents[2]
PHASE_RULES_VERSION = "phase-rules-v1"

BASE: dict[str, dict[str, Any]] = {
    "cowrie.session.connect": {
        "src_port": 40000,
        "dst_ip": "192.0.2.10",
        "dst_port": 2222,
        "protocol": "ssh",
    },
    "cowrie.client.version": {"version": "SSH-2.0-Go"},
    "cowrie.login.failed": {"username": "root", "password": "123456"},
    "cowrie.login.success": {"username": "root", "password": "toor"},
    "cowrie.command.input": {"input": "uname -a"},
    "cowrie.command.failed": {"input": "nosuch"},
    "cowrie.session.file_download": {
        "url": "http://198.51.100.40/x.sh",
        "shasum": "a" * 64,
    },
    "cowrie.session.file_upload": {"filename": "up.bin", "shasum": "b" * 64},
    "cowrie.client.kex": {"hassh": "x"},
    "cowrie.session.closed": {"duration": "1.0"},
}


def cowrie_line(
    eventid: str,
    *,
    session: str = "a1b2c3d4e5f60001",
    timestamp: str = "2025-03-01T10:00:00.000000Z",
    src_ip: str = "203.0.113.7",
    **fields: Any,
) -> bytes:
    record = {
        "eventid": eventid,
        **BASE.get(eventid, {}),
        **fields,
        "session": session,
        "timestamp": timestamp,
        "src_ip": src_ip,
    }
    return json.dumps(record).encode("ascii")


def accepted(eventid: str, **kwargs: Any) -> Accepted:
    result = parse_line(cowrie_line(eventid, **kwargs))
    assert isinstance(result, Accepted), result
    return result


def load_phase_rules() -> PhaseRules:
    return load_config(REPO_ROOT / "config").phase_rules[PHASE_RULES_VERSION].model
