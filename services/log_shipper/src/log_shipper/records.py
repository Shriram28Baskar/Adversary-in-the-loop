"""Staging records built by the shipper (``intel_raw``; migration 0003, 0014).

Every record is data for the database, never code: payloads are either the
validated line verbatim (events) or canonical JSON built by this module
(quarantine, heartbeat), so attacker bytes are always JSON-escaped and bounded.
Reason codes and source references are produced by the shipper, never copied
from content.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

from aitl_common.canonical_json import dumps, sha256_hex
from log_shipper.parser import Accepted, Rejected

__all__ = [
    "PREVIEW_CHARS",
    "EventRecord",
    "HeartbeatRecord",
    "QuarantineRecord",
    "event_record",
    "quarantine_record",
]

PREVIEW_CHARS: Final = 2048
Mode = Literal["live", "fixture"]


@dataclass(frozen=True, slots=True)
class EventRecord:
    ingest_mode: Mode
    source_ref: str
    payload: str
    payload_sha256: str
    session: str


@dataclass(frozen=True, slots=True)
class QuarantineRecord:
    stage: Literal["shipper_parse", "shipper_validate"]
    reason_code: str
    payload: str


@dataclass(frozen=True, slots=True)
class HeartbeatRecord:
    ingest_mode: Mode
    payload: str
    payload_sha256: str


def event_record(mode: Mode, source_ref: str, accepted: Accepted) -> EventRecord:
    return EventRecord(
        mode, source_ref, accepted.payload, accepted.payload_sha256, accepted.session
    )


def quarantine_payload(source_ref: str, reason: str, line: bytes) -> str:
    """Bounded, escaped evidence of a rejected line; never the raw bytes."""
    preview = line[: PREVIEW_CHARS * 4].decode("utf-8", errors="replace")[:PREVIEW_CHARS]
    return dumps(
        {
            "reason": reason,
            "source_ref": source_ref,
            "line_bytes": len(line),
            "line_sha256": sha256_hex(line),
            "preview": preview,
            "preview_truncated": len(preview) < len(line.decode("utf-8", errors="replace")),
        }
    ).decode("utf-8")


def quarantine_record(source_ref: str, rejected: Rejected) -> QuarantineRecord:
    return QuarantineRecord(
        rejected.stage,
        rejected.reason,
        quarantine_payload(source_ref, rejected.reason, rejected.line),
    )


def quota_record(source_ref: str, session: str, limit: int) -> QuarantineRecord:
    """One record per session the first time it exceeds its byte quota."""
    payload = dumps(
        {
            "reason": "quota.session_bytes",
            "source_ref": source_ref,
            "session": session,  # validated [0-9a-f]{8,32} by the parser
            "limit_bytes": limit,
        }
    ).decode("utf-8")
    return QuarantineRecord("shipper_validate", "quota.session_bytes", payload)


def heartbeat_record(
    mode: Mode, counters: dict[str, int], lag_seconds: int, emitted_at: str
) -> HeartbeatRecord:
    payload = dumps(
        {
            "type": "heartbeat",
            "mode": mode,
            "counters": counters,
            "lag_seconds": lag_seconds,
            "emitted_at": emitted_at,
        }
    ).decode("utf-8")
    return HeartbeatRecord(mode, payload, sha256_hex(payload.encode("utf-8")))
