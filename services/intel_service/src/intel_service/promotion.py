"""Promotion of staged telemetry into sessions, events and behaviors (FR-005, FR-006, FR-048).

The only module that writes ``intel.attack_session``, ``intel.attack_event``,
``intel.attacker_behavior`` and ``intel.behavior_event`` (FR-005b; static
test). Runs as ``intel_svc``; every statement is parameterized.

One run (ADR-024):

1. **Scan** every staged ``event`` row not yet handled - not referenced by an
   ``attack_event`` nor by a ``promotion``-stage quarantine row - in
   ``raw_record_id`` order, re-validating each payload with the shared strict
   parser (CLAUDE.md Security Principle 19). Only (id, session key, is-close)
   is kept per row. Operational safety bound (not behavioral semantics): more
   than ``max_unhandled_events`` stops the run before any write.
2. **Quarantine** rows that no longer validate (``promotion.invalid_payload``).
3. For each session key, in sorted key order:

   - already promoted  -> every new event is ``promotion.late_event`` (D3);
   - no ``session_closed`` event yet -> pending: counted, not promoted (D2);
   - more than ``max_session_events`` -> every event is quarantined as
     ``promotion.session_too_large`` (operational safety bound, not a judgement
     about the attacker; never a partial promotion);
   - otherwise plan it (D1, D4-D6) and write the session, its events, its
     behaviors and their links in **one transaction**, or quarantine every
     event of a rejected session with the plan's reason.

No clock, no randomness: the outcome depends only on the staged rows
(including their ``raw_record_id`` values), the phase-rule artifact and this
code. Re-running is a no-op for handled rows. See ARCHITECTURE.md §10 for the
exact determinism guarantee.
"""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from typing import Final

from sqlalchemy import Connection, Engine, insert, text

from aitl_common.canonical_json import dumps
from aitl_common.config.schemas.intel import PhaseRules
from aitl_common.db.models.intel import AttackerBehavior, AttackEvent, AttackSession, BehaviorEvent
from aitl_common.db.models.intel_raw import QuarantineRecord
from aitl_common.logging import correlation_scope, log_event
from aitl_common.telemetry.cowrie import Accepted, parse_line
from intel_service.events import SOURCE_TYPE_BY_MODE, NormalizedEvent, normalize_event
from intel_service.sessions import SessionPlan, SessionRejected, plan_session

__all__ = [
    "INTEL_ROLE",
    "INVALID_PAYLOAD",
    "LATE_EVENT",
    "SESSION_TOO_LARGE",
    "Promoter",
    "PromotionBoundError",
    "PromotionLimits",
    "RunResult",
]

INTEL_ROLE: Final = "intel_svc"
INVALID_PAYLOAD: Final = "promotion.invalid_payload"
LATE_EVENT: Final = "promotion.late_event"
SESSION_TOO_LARGE: Final = "promotion.session_too_large"

_log = logging.getLogger("intel_service.promotion")

_UNHANDLED: Final = text(
    "SELECT r.id, r.ingest_mode, r.payload FROM intel_raw.raw_ingest_record r "
    "WHERE r.kind = 'event' AND r.id > :after "
    "AND NOT EXISTS (SELECT 1 FROM intel.attack_event e WHERE e.raw_record_id = r.id) "
    "AND NOT EXISTS (SELECT 1 FROM intel_raw.quarantine_record q "
    "WHERE q.raw_record_id = r.id AND q.stage = 'promotion') "
    "ORDER BY r.id LIMIT :limit"
)
_BY_IDS: Final = text(
    "SELECT id, ingest_mode, payload FROM intel_raw.raw_ingest_record "
    "WHERE kind = 'event' AND id = ANY(:ids)"
)
_SESSION_EXISTS: Final = text(
    "SELECT 1 FROM intel.attack_session "
    "WHERE source_type = CAST(:source_type AS public.source_type) "
    "AND cowrie_session_id = :cowrie_session_id"
)


class PromotionBoundError(RuntimeError):
    """More unhandled staged events than one run may hold: nothing was written."""


@dataclass(frozen=True, slots=True)
class PromotionLimits:
    max_unhandled_events: int = 200_000
    max_session_events: int = 10_000
    page_size: int = 1_000


@dataclass
class RunResult:
    sessions_promoted: int = 0
    events_promoted: int = 0
    behaviors_created: int = 0
    pending_sessions: int = 0
    pending_events: int = 0
    failed_sessions: int = 0
    quarantined: Counter[str] = field(default_factory=Counter)


@dataclass(frozen=True, slots=True)
class _Row:
    raw_record_id: int
    is_close: bool


SessionKey = tuple[str, str]  # (source_type, cowrie_session_id)


def _quarantine_payload(reason: str, raw_record_id: int, detail: str | None = None) -> str:
    # Platform-generated metadata only; the evidence stays in its raw row.
    document: dict[str, object] = {"reason": reason, "raw_record_id": raw_record_id}
    if detail is not None:
        document["detail"] = detail
    return dumps(document).decode("utf-8")


class Promoter:
    def __init__(
        self,
        engine: Engine,
        rules: PhaseRules,
        limits: PromotionLimits | None = None,
    ) -> None:
        with engine.connect() as connection:
            user = connection.execute(text("SELECT current_user")).scalar_one()
        if user != INTEL_ROLE:
            raise PermissionError(f"promotion runs only as {INTEL_ROLE}")
        self.engine = engine
        self.rules = rules
        self.limits = limits or PromotionLimits()

    # --- scan -----------------------------------------------------------------------

    def _scan(self) -> tuple[dict[SessionKey, list[_Row]], list[tuple[int, str]]]:
        groups: dict[SessionKey, list[_Row]] = {}
        invalid: list[tuple[int, str]] = []
        seen, after = 0, 0
        with self.engine.connect() as connection:
            while True:
                page = connection.execute(
                    _UNHANDLED, {"after": after, "limit": self.limits.page_size}
                ).all()
                if not page:
                    break
                for raw_record_id, ingest_mode, payload in page:
                    after = raw_record_id
                    seen += 1
                    if seen > self.limits.max_unhandled_events:
                        raise PromotionBoundError(
                            f"more than {self.limits.max_unhandled_events} unhandled events"
                        )
                    parsed = parse_line(payload.encode("utf-8"))
                    if not isinstance(parsed, Accepted):
                        invalid.append((raw_record_id, parsed.reason))
                        continue
                    key = (SOURCE_TYPE_BY_MODE[ingest_mode], parsed.session)
                    groups.setdefault(key, []).append(
                        _Row(raw_record_id, parsed.event_type == "session_closed")
                    )
        return groups, invalid

    # --- writes -----------------------------------------------------------------------

    @staticmethod
    def _quarantine(
        connection: Connection, reason: str, rows: Iterable[tuple[int, str | None]]
    ) -> int:
        values = [
            {
                "raw_record_id": raw_record_id,
                "stage": "promotion",
                "reason_code": reason,
                "payload": _quarantine_payload(reason, raw_record_id, detail),
            }
            for raw_record_id, detail in rows
        ]
        if values:
            connection.execute(insert(QuarantineRecord), values)
        return len(values)

    def _load(self, connection: Connection, rows: Sequence[_Row]) -> list[NormalizedEvent]:
        records = connection.execute(_BY_IDS, {"ids": [r.raw_record_id for r in rows]}).all()
        events = []
        for raw_record_id, ingest_mode, payload in records:
            parsed = parse_line(payload.encode("utf-8"))
            if not isinstance(parsed, Accepted):  # validated in the scan moments ago
                raise RuntimeError("staged payload changed between scan and load")
            events.append(normalize_event(raw_record_id, ingest_mode, parsed))
        if len(events) != len(rows):
            raise RuntimeError("staged rows changed between scan and load")
        return events

    @staticmethod
    def _write(connection: Connection, plan: SessionPlan) -> None:
        connection.execute(
            insert(AttackSession),
            {
                "id": plan.id,
                "source_type": plan.source_type,
                "cowrie_session_id": plan.cowrie_session_id,
                "src_ip": plan.src_ip,
                "src_port": plan.src_port,
                "first_event_at": plan.first_event_at,
                "first_raw_record_id": plan.first_raw_record_id,
            },
        )
        connection.execute(
            insert(AttackEvent),
            [
                {
                    "id": plan.event_id(item.seq),
                    "session_id": plan.id,
                    "raw_record_id": item.event.raw_record_id,
                    "seq": item.seq,
                    "event_type": item.event.event_type,
                    "occurred_at": item.event.occurred_at,
                    "raw_text": item.event.raw_text,
                    "normalized_text": item.event.normalized_text,
                    "truncated": item.event.truncated,
                    "username": item.event.username,
                    "attempted_secret": item.event.attempted_secret,
                    "artifact_sha256": item.event.artifact_sha256,
                    "artifact_size": None,
                }
                for item in plan.events
            ],
        )
        connection.execute(
            insert(AttackerBehavior),
            [
                {
                    "id": plan.behavior_id(behavior.ordinal),
                    "session_id": plan.id,
                    "ordinal": behavior.ordinal,
                    "phase": behavior.phase,
                    "phase_rules_version": plan.phase_rules_version,
                    "started_at": behavior.started_at,
                    "ended_at": behavior.ended_at,
                }
                for behavior in plan.behaviors
            ],
        )
        connection.execute(
            insert(BehaviorEvent),
            [
                {
                    "behavior_id": plan.behavior_id(behavior.ordinal),
                    "event_id": plan.event_id(seq),
                    "session_id": plan.id,
                }
                for behavior in plan.behaviors
                for seq in behavior.event_seqs
            ],
        )

    # --- run ---------------------------------------------------------------------------

    def _sessions(
        self, groups: dict[SessionKey, list[_Row]]
    ) -> Iterator[tuple[SessionKey, list[_Row]]]:
        for key in sorted(groups):
            yield key, groups[key]

    def run(self) -> RunResult:
        result = RunResult()
        with correlation_scope():
            groups, invalid = self._scan()
            if invalid:
                with self.engine.begin() as connection:
                    count = self._quarantine(
                        connection, INVALID_PAYLOAD, [(i, reason) for i, reason in invalid]
                    )
                result.quarantined[INVALID_PAYLOAD] += count
            for (source_type, cowrie_session_id), rows in self._sessions(groups):
                self._promote_one(source_type, cowrie_session_id, rows, result)
            log_event(
                _log,
                logging.INFO,
                "promotion.run",
                sessions_promoted=result.sessions_promoted,
                events_promoted=result.events_promoted,
                behaviors_created=result.behaviors_created,
                pending_sessions=result.pending_sessions,
                pending_events=result.pending_events,
                failed_sessions=result.failed_sessions,
                quarantined=dict(sorted(result.quarantined.items())),
                phase_rules_version=self.rules.version,
            )
        return result

    def _promote_one(
        self, source_type: str, cowrie_session_id: str, rows: list[_Row], result: RunResult
    ) -> None:
        ids = [(r.raw_record_id, None) for r in rows]
        try:
            with self.engine.begin() as connection:
                exists = connection.execute(
                    _SESSION_EXISTS,
                    {"source_type": source_type, "cowrie_session_id": cowrie_session_id},
                ).first()
                if exists is not None:
                    result.quarantined[LATE_EVENT] += self._quarantine(connection, LATE_EVENT, ids)
                    return
                if not any(r.is_close for r in rows):
                    result.pending_sessions += 1
                    result.pending_events += len(rows)
                    return
                if len(rows) > self.limits.max_session_events:
                    result.quarantined[SESSION_TOO_LARGE] += self._quarantine(
                        connection, SESSION_TOO_LARGE, ids
                    )
                    return
                plan = plan_session(self._load(connection, rows), self.rules)
                if isinstance(plan, SessionRejected):
                    result.quarantined[plan.reason] += self._quarantine(
                        connection, plan.reason, ids
                    )
                    return
                self._write(connection, plan)
        except Exception as exc:  # noqa: BLE001 - one session's failure never promotes it
            # The transaction rolled back: nothing of this session was written, so
            # a later run retries it from its unchanged staged rows.
            result.failed_sessions += 1
            log_event(
                _log,
                logging.ERROR,
                "promotion.session_failed",
                source_type=source_type,
                error_class=type(exc).__name__,
            )
            return
        result.sessions_promoted += 1
        result.events_promoted += len(plan.events)
        result.behaviors_created += len(plan.behaviors)
