"""The shipper loop: read -> validate -> quota -> write -> commit positions.

Fail-closed properties:
- Positions advance only after the batch's transaction committed; a database
  failure leaves them untouched, so the same lines are retried (and the
  staging keys make the retry insert nothing twice).
- Every line becomes exactly one of: a staged event, a quarantine record, a
  duplicate (already staged), or a quota drop (counted and reported).
- Logs carry counts, reason codes and correlation IDs only - never line
  content, usernames, passwords, commands or addresses (SEC-009).
"""

from __future__ import annotations

import logging
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from aitl_common.canonical_json import dumps
from aitl_common.logging import correlation_scope, log_event
from log_shipper.config import ShipperSettings
from log_shipper.parser import MAX_LINE_BYTES, Rejected, parse_line
from log_shipper.quota import RateLimiter, SessionByteQuota
from log_shipper.reader import (
    FIXTURE_FILE_PATTERN,
    LIVE_FILE_PATTERN,
    Line,
    SourceReader,
    StateStore,
)
from log_shipper.records import (
    EventRecord,
    QuarantineRecord,
    event_record,
    heartbeat_record,
    quarantine_payload,
    quarantine_record,
    quota_record,
)
from log_shipper.writer import StagingWriter

__all__ = ["HEALTH_FILE", "Shipper"]

HEALTH_FILE = "health.json"
_log = logging.getLogger("log_shipper")


@dataclass
class Counters:
    shipped: int = 0
    duplicates: int = 0
    quarantined: int = 0
    dropped: int = 0
    reasons: Counter[str] = field(default_factory=Counter)

    def snapshot(self) -> dict[str, int]:
        return {
            "shipped": self.shipped,
            "duplicates": self.duplicates,
            "quarantined": self.quarantined,
            "dropped": self.dropped,
        }


class Shipper:
    def __init__(
        self,
        settings: ShipperSettings,
        writer: StagingWriter,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        wall_clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.settings = settings
        self.writer = writer
        self.clock = clock
        self.sleep = sleep
        self.wall_clock = wall_clock
        self.state = StateStore(settings.state_dir)
        self.reader = SourceReader(
            settings.source_dir,
            LIVE_FILE_PATTERN if settings.mode == "live" else FIXTURE_FILE_PATTERN,
            max_line_bytes=MAX_LINE_BYTES,
            max_bytes=settings.max_bytes_per_cycle,
            max_lines=settings.batch_lines,
            complete_final_line=settings.mode == "fixture",
        )
        self.quota = SessionByteQuota(settings.session_max_bytes, settings.max_tracked_sessions)
        self.rate = RateLimiter(settings.records_per_minute, clock=clock, sleep=sleep)
        self.counters = Counters()
        self.last_heartbeat: float | None = None
        self.caught_up_at = clock()

    def run_cycle(self) -> bool:
        """One bounded cycle. Returns True if unread data remains."""
        with correlation_scope():
            cycle = self.reader.read_cycle(self.state.positions)
            events: list[EventRecord] = []
            quarantine: list[QuarantineRecord] = []
            dropped = 0
            reasons: Counter[str] = Counter()
            for item in cycle.items:
                if not isinstance(item, Line):
                    quarantine.append(
                        QuarantineRecord(
                            "shipper_parse",
                            "line.too_long",
                            quarantine_payload(item.source_ref, "line.too_long", item.prefix),
                        )
                    )
                    reasons["line.too_long"] += 1
                    continue
                parsed = parse_line(item.data)
                if isinstance(parsed, Rejected):
                    quarantine.append(quarantine_record(item.source_ref, parsed))
                    reasons[parsed.reason] += 1
                    continue
                admission = self.quota.admit(parsed.session, len(item.data))
                if admission == "ok":
                    events.append(event_record(self.settings.mode, item.source_ref, parsed))
                    continue
                dropped += 1
                if admission == "first_exceeded":
                    quarantine.append(
                        quota_record(item.source_ref, parsed.session, self.quota.limit_bytes)
                    )
                    reasons["quota.session_bytes"] += 1
            if events or quarantine:
                self.rate.acquire(len(events) + len(quarantine))
                result = self.writer.write(events, quarantine)
            else:
                result = None
            # Only after the transaction committed.
            self.state.commit(cycle.positions)
            if result is not None:
                self.counters.shipped += result.events_inserted
                self.counters.duplicates += result.events_duplicate + result.quarantine_duplicate
                self.counters.quarantined += result.quarantine_inserted
            self.counters.dropped += dropped
            self.counters.reasons.update(reasons)
            if cycle.items:
                log_event(
                    _log,
                    logging.INFO,
                    "shipper.cycle",
                    mode=self.settings.mode,
                    lines=len(cycle.items),
                    shipped=0 if result is None else result.events_inserted,
                    duplicates=0 if result is None else result.events_duplicate,
                    quarantined=0 if result is None else result.quarantine_inserted,
                    dropped=dropped,
                    reasons=dict(sorted(reasons.items())),
                )
            if not cycle.pending:
                self.caught_up_at = self.clock()
            return cycle.pending

    def heartbeat_due(self) -> bool:
        return (
            self.last_heartbeat is None
            or self.clock() - self.last_heartbeat >= self.settings.heartbeat_seconds
        )

    def heartbeat(self, pending: bool) -> None:
        lag = 0 if not pending else int(self.clock() - self.caught_up_at)
        emitted_at = self.wall_clock().isoformat()
        self.writer.heartbeat(
            heartbeat_record(self.settings.mode, self.counters.snapshot(), lag, emitted_at)
        )
        self.last_heartbeat = self.clock()
        _write_health(self.settings.state_dir, emitted_at)
        log_event(_log, logging.INFO, "shipper.heartbeat", mode=self.settings.mode, lag_seconds=lag)

    def run_forever(self, should_stop: Callable[[], bool]) -> None:
        backoff = 1.0
        while not should_stop():
            try:
                pending = self.run_cycle()
                if self.heartbeat_due():
                    self.heartbeat(pending)
                backoff = 1.0
                if not pending:
                    self.sleep(self.settings.poll_seconds)
            except Exception as exc:  # noqa: BLE001 - keep positions; retry the same lines
                log_event(
                    _log,
                    logging.ERROR,
                    "shipper.cycle_failed",
                    error_type=type(exc).__name__,
                    retry_in_seconds=backoff,
                )
                self.sleep(backoff)
                backoff = min(backoff * 2, 60.0)


def _write_health(state_dir: Path, emitted_at: str) -> None:
    tmp = state_dir / f"{HEALTH_FILE}.tmp"
    tmp.write_bytes(dumps({"last_heartbeat": emitted_at}))
    tmp.replace(state_dir / HEALTH_FILE)
