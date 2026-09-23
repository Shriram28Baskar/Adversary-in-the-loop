"""Shipper settings from deployment environment only (never from telemetry).

``SHIPPER_MODE`` fixes the ingest mode for the whole process: ``live`` rows are
promoted as ``source_type = honeypot`` and ``fixture`` rows as ``synthetic``
(ARCHITECTURE.md §9; FR-005, FR-005b). No line can change it. Every limit has
a default and a hard ceiling; a missing, malformed or out-of-range value
refuses to start (fail closed), never falls back silently.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, cast

from log_shipper.parser import MAX_LINE_BYTES

__all__ = ["LIMITS", "ConfigError", "ShipperSettings"]

Mode = Literal["live", "fixture"]

# name -> (default, minimum, maximum)
LIMITS: Final[dict[str, tuple[int, int, int]]] = {
    "SHIPPER_BATCH_LINES": (200, 1, 1000),
    "SHIPPER_MAX_BYTES_PER_CYCLE": (4 * 1024 * 1024, MAX_LINE_BYTES + 1, 32 * 1024 * 1024),
    "SHIPPER_RECORDS_PER_MINUTE": (6000, 1, 60000),
    "SHIPPER_SESSION_MAX_BYTES": (1024 * 1024, 1024, 64 * 1024 * 1024),
    "SHIPPER_MAX_TRACKED_SESSIONS": (10000, 1, 100000),
    "SHIPPER_POLL_SECONDS": (2, 1, 60),
    "SHIPPER_HEARTBEAT_SECONDS": (60, 10, 3600),
}


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class ShipperSettings:
    mode: Mode
    source_dir: Path
    state_dir: Path
    batch_lines: int
    max_bytes_per_cycle: int
    records_per_minute: int
    session_max_bytes: int
    max_tracked_sessions: int
    poll_seconds: int
    heartbeat_seconds: int

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> ShipperSettings:
        mode = env.get("SHIPPER_MODE")
        if mode not in ("live", "fixture"):
            raise ConfigError("SHIPPER_MODE must be 'live' or 'fixture'")
        dirs = {}
        for name in ("SHIPPER_SOURCE_DIR", "SHIPPER_STATE_DIR"):
            directory = env.get(name)
            if not directory or not Path(directory).is_absolute() or ".." in Path(directory).parts:
                raise ConfigError(f"{name} must be an absolute path")
            dirs[name] = Path(directory)
        if dirs["SHIPPER_SOURCE_DIR"] == dirs["SHIPPER_STATE_DIR"]:
            raise ConfigError("source and state directories must differ")
        limits = {}
        for name, (default, low, high) in LIMITS.items():
            raw = env.get(name)
            if raw is None:
                limits[name] = default
                continue
            if not raw.isascii() or not raw.isdigit():
                raise ConfigError(f"{name} must be a decimal integer")
            value = int(raw)
            if not low <= value <= high:
                raise ConfigError(f"{name} must be within {low}..{high}")
            limits[name] = value
        return cls(
            mode=cast(Mode, mode),
            source_dir=dirs["SHIPPER_SOURCE_DIR"],
            state_dir=dirs["SHIPPER_STATE_DIR"],
            batch_lines=limits["SHIPPER_BATCH_LINES"],
            max_bytes_per_cycle=limits["SHIPPER_MAX_BYTES_PER_CYCLE"],
            records_per_minute=limits["SHIPPER_RECORDS_PER_MINUTE"],
            session_max_bytes=limits["SHIPPER_SESSION_MAX_BYTES"],
            max_tracked_sessions=limits["SHIPPER_MAX_TRACKED_SESSIONS"],
            poll_seconds=limits["SHIPPER_POLL_SECONDS"],
            heartbeat_seconds=limits["SHIPPER_HEARTBEAT_SECONDS"],
        )
