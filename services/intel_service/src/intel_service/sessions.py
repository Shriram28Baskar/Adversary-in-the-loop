"""Session reconstruction plan for one closed session (FR-005, FR-006; ADR-024 D1, D4-D6).

Pure: given every staged event of one ``(source_type, cowrie_session_id)``,
either a complete ``SessionPlan`` (session row values, sequenced events,
behaviors, deterministic identifiers) or a ``SessionRejected`` reason.

D6: the session's network fields belong to its ``session_connect`` event.
Cowrie emits exactly one per session, so none is ``promotion.no_connect_event``
and more than one - or any event whose ``src_ip`` differs from the connect
event's - is ``promotion.conflicting_field``. Nothing is chosen between
conflicting values; the whole session is rejected (and quarantined by the
caller, FR-048).
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Final

from aitl_common.config.schemas.intel import PhaseRules
from intel_service import identity
from intel_service.events import NormalizedEvent
from intel_service.reconstruction import Behavior, SequencedEvent, order_events, reconstruct

__all__ = [
    "CONFLICTING_FIELD",
    "NO_CONNECT_EVENT",
    "SessionPlan",
    "SessionRejected",
    "plan_session",
]

NO_CONNECT_EVENT: Final = "promotion.no_connect_event"
CONFLICTING_FIELD: Final = "promotion.conflicting_field"


@dataclass(frozen=True, slots=True)
class SessionPlan:
    id: uuid.UUID
    source_type: str
    cowrie_session_id: str
    src_ip: str
    src_port: int
    first_event_at: datetime
    first_raw_record_id: int
    events: tuple[SequencedEvent, ...]
    behaviors: tuple[Behavior, ...]
    phase_rules_version: str

    def event_id(self, seq: int) -> uuid.UUID:
        return identity.event_id(self.source_type, self.cowrie_session_id, seq)

    def behavior_id(self, ordinal: int) -> uuid.UUID:
        return identity.behavior_id(self.source_type, self.cowrie_session_id, ordinal)


@dataclass(frozen=True, slots=True)
class SessionRejected:
    reason: str


def plan_session(
    events: Sequence[NormalizedEvent], rules: PhaseRules
) -> SessionPlan | SessionRejected:
    keys = {(e.source_type, e.cowrie_session_id) for e in events}
    if len(keys) != 1:
        raise ValueError("plan_session needs the events of exactly one session")
    ((source_type, cowrie_session_id),) = keys

    connects = [e for e in events if e.event_type == "session_connect"]
    if not connects:
        return SessionRejected(NO_CONNECT_EVENT)
    if len(connects) > 1:
        return SessionRejected(CONFLICTING_FIELD)
    (connect,) = connects
    if connect.src_ip is None or connect.src_port is None:
        return SessionRejected(NO_CONNECT_EVENT)  # not a valid connect event
    if any(e.src_ip is not None and e.src_ip != connect.src_ip for e in events):
        return SessionRejected(CONFLICTING_FIELD)

    ordered = order_events(events)
    first = ordered[0].event
    return SessionPlan(
        id=identity.session_id(source_type, cowrie_session_id),
        source_type=source_type,
        cowrie_session_id=cowrie_session_id,
        src_ip=connect.src_ip,
        src_port=connect.src_port,
        first_event_at=first.occurred_at,
        first_raw_record_id=first.raw_record_id,
        events=ordered,
        behaviors=reconstruct(ordered, rules),
        phase_rules_version=rules.version,
    )
