"""INSERT-only staging writer (``ingest_writer``; FR-004b).

Parameterized statements only: attacker-derived text is always a bound
parameter, never part of SQL. Each batch is one transaction. Inserts use an
untargeted ``ON CONFLICT DO NOTHING``, which needs no privilege beyond INSERT
(a targeted conflict clause or RETURNING would need SELECT, which the role
does not have), so a replayed line inserts nothing (migration 0014).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from sqlalchemy import Engine, text

from log_shipper.records import EventRecord, HeartbeatRecord, QuarantineRecord

__all__ = ["INGEST_ROLE", "StagingWriter", "WriteResult"]

INGEST_ROLE: Final = "ingest_writer"

_INSERT_RAW: Final = text(
    "INSERT INTO intel_raw.raw_ingest_record "
    "(kind, ingest_mode, source_ref, payload, payload_sha256) "
    "VALUES (:kind, :ingest_mode, :source_ref, :payload, :payload_sha256) "
    "ON CONFLICT DO NOTHING"
)
_INSERT_QUARANTINE: Final = text(
    "INSERT INTO intel_raw.quarantine_record (stage, reason_code, payload) "
    "VALUES (:stage, :reason_code, :payload) ON CONFLICT DO NOTHING"
)


@dataclass(frozen=True)
class WriteResult:
    events_inserted: int
    events_duplicate: int
    quarantine_inserted: int
    quarantine_duplicate: int


class StagingWriter:
    def __init__(self, engine: Engine) -> None:
        with engine.connect() as connection:
            user = connection.execute(text("SELECT current_user")).scalar_one()
        if user != INGEST_ROLE:
            raise PermissionError(f"the shipper writes only as {INGEST_ROLE}")
        self.engine = engine

    def write(
        self, events: Sequence[EventRecord], quarantine: Sequence[QuarantineRecord]
    ) -> WriteResult:
        inserted = duplicate = q_inserted = q_duplicate = 0
        with self.engine.begin() as connection:
            for event in events:
                result = connection.execute(
                    _INSERT_RAW,
                    {
                        "kind": "event",
                        "ingest_mode": event.ingest_mode,
                        "source_ref": event.source_ref,
                        "payload": event.payload,
                        "payload_sha256": event.payload_sha256,
                    },
                )
                if result.rowcount == 1:
                    inserted += 1
                else:
                    duplicate += 1
            for record in quarantine:
                result = connection.execute(
                    _INSERT_QUARANTINE,
                    {
                        "stage": record.stage,
                        "reason_code": record.reason_code,
                        "payload": record.payload,
                    },
                )
                if result.rowcount == 1:
                    q_inserted += 1
                else:
                    q_duplicate += 1
        return WriteResult(inserted, duplicate, q_inserted, q_duplicate)

    def heartbeat(self, record: HeartbeatRecord) -> None:
        with self.engine.begin() as connection:
            connection.execute(
                _INSERT_RAW,
                {
                    "kind": "heartbeat",
                    "ingest_mode": record.ingest_mode,
                    "source_ref": "heartbeat",
                    "payload": record.payload,
                    "payload_sha256": record.payload_sha256,
                },
            )
