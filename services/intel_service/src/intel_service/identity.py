"""Deterministic identifiers for P4 reconstruction objects (ADR-024 D5).

Identical telemetry and identical artifact/code versions must produce an
identical reconstruction, identifiers included. Each P4-created row therefore
gets an RFC 4122 name-based UUID (version 5) in a fixed, repository-owned
namespace. The name is the P0 canonical JSON of the defined identity inputs,
and nothing else:

- AttackSession    : (source_type, cowrie_session_id)
- AttackEvent      : (session identity, seq)
- AttackerBehavior : (session identity, ordinal)

``source_type`` comes from deployment configuration (ingest mode), and the
Cowrie session ID is a validated hex token; ``seq`` and ``ordinal`` are
positions computed by reconstruction. No random value, clock, process state,
database insertion order, file order or attacker free text enters a name.
The namespaces below are constants: changing one changes every identifier,
so they are pinned by tests.
"""

from __future__ import annotations

import uuid
from typing import Final

from aitl_common.canonical_json import dumps

__all__ = [
    "BEHAVIOR_NAMESPACE",
    "EVENT_NAMESPACE",
    "SESSION_NAMESPACE",
    "behavior_id",
    "event_id",
    "session_id",
]

SESSION_NAMESPACE: Final = uuid.UUID("0f2c7f6e-6a0b-5c1e-9a43-1d7e0b3a5c01")
EVENT_NAMESPACE: Final = uuid.UUID("5b8e1d24-3f6a-5e2b-8c17-9a0d4e6f2b02")
BEHAVIOR_NAMESPACE: Final = uuid.UUID("a3d94c7b-0e25-5f8d-b6a1-4c2e8f1d7a03")


def _session_identity(source_type: str, cowrie_session_id: str) -> dict[str, str]:
    return {"source_type": source_type, "cowrie_session_id": cowrie_session_id}


def _name(value: object) -> str:
    return dumps(value).decode("utf-8")


def session_id(source_type: str, cowrie_session_id: str) -> uuid.UUID:
    return uuid.uuid5(SESSION_NAMESPACE, _name(_session_identity(source_type, cowrie_session_id)))


def event_id(source_type: str, cowrie_session_id: str, seq: int) -> uuid.UUID:
    identity = {"session": _session_identity(source_type, cowrie_session_id), "seq": seq}
    return uuid.uuid5(EVENT_NAMESPACE, _name(identity))


def behavior_id(source_type: str, cowrie_session_id: str, ordinal: int) -> uuid.UUID:
    identity = {"session": _session_identity(source_type, cowrie_session_id), "ordinal": ordinal}
    return uuid.uuid5(BEHAVIOR_NAMESPACE, _name(identity))
