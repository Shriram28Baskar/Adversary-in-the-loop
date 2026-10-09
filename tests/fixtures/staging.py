"""Staging and projection helpers for P4 integration tests (real PostgreSQL).

Staged rows enter either through the real Log Shipper (the P3 path) or, for
focused cases, as the ``ingest_writer`` role with the same INSERT the shipper
issues. A test that must pin ``raw_record_id`` values inserts as the cluster
administrator with ``OVERRIDING SYSTEM VALUE`` - the only way to put chosen
identities into the append-only staging table in a chosen physical order.
"""

from __future__ import annotations

import shutil
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from sqlalchemy import Engine

from aitl_common.canonical_json import sha256_hex
from aitl_common.db.engine import DatabaseSettings, create_role_engine
from intel_service.promotion import Promoter, PromotionLimits
from log_shipper.config import ShipperSettings
from log_shipper.service import Shipper
from log_shipper.writer import StagingWriter
from tests.fixtures import honeypot_corpus
from tests.fixtures.cowrie_events import load_phase_rules
from tests.pg_harness import Cluster

INSERT_STAGED = (
    "INSERT INTO intel_raw.raw_ingest_record "
    "(kind, ingest_mode, source_ref, payload, payload_sha256) "
    "VALUES ('event', %s, %s, %s, %s)"
)
INSERT_STAGED_WITH_ID = (
    "INSERT INTO intel_raw.raw_ingest_record "
    "(id, kind, ingest_mode, source_ref, payload, payload_sha256) OVERRIDING SYSTEM VALUE "
    "VALUES (%s, 'event', %s, %s, %s, %s)"
)


def role_engine(pg: Cluster, dbname: str, role: str) -> Engine:
    settings = DatabaseSettings(
        host=pg.host, port=pg.port, dbname=dbname, user=role, password=pg.passwords[role]
    )
    return create_role_engine(role, settings)


def ingest_corpus(
    pg: Cluster, dbname: str, workdir: Path, *, source: Path | None = None, mode: str = "fixture"
) -> None:
    """The P3 path: the real shipper over a directory (default: the synthetic corpus)."""
    state = workdir / f"state-{len(list(workdir.glob('state-*')))}"
    state.mkdir()
    if source is None:
        source = workdir / "corpus"
        if not source.exists():
            shutil.copytree(honeypot_corpus.CORPUS_DIR, source)
    settings = ShipperSettings.from_env(
        {"SHIPPER_MODE": mode, "SHIPPER_SOURCE_DIR": str(source), "SHIPPER_STATE_DIR": str(state)}
    )
    engine = role_engine(pg, dbname, "ingest_writer")
    try:
        shipper = Shipper(settings, StagingWriter(engine), sleep=lambda _: None)
        for _ in range(1000):
            if not shipper.run_cycle():
                return
        raise AssertionError("shipper did not drain")
    finally:
        engine.dispose()


def stage(pg: Cluster, dbname: str, lines: Iterable[bytes], mode: str = "fixture") -> list[int]:
    """Stage lines as ingest_writer, in order; returns their raw_record_ids."""
    with pg.connect(dbname, "ingest_writer") as conn:
        for index, line in enumerate(lines):
            text = line.decode("utf-8", errors="replace")
            conn.execute(
                INSERT_STAGED, (mode, f"test:{index}", text, sha256_hex(text.encode("utf-8")))
            )
        conn.commit()
    with pg.admin(dbname) as conn:
        rows = conn.execute(
            "SELECT id FROM intel_raw.raw_ingest_record WHERE kind = 'event' ORDER BY id"
        ).fetchall()
    return [int(str(row[0])) for row in rows]


def stage_with_ids(
    pg: Cluster, dbname: str, rows: Sequence[tuple[int, bytes]], mode: str = "fixture"
) -> None:
    """Stage (raw_record_id, line) pairs in exactly the given physical order."""
    with pg.admin(dbname) as conn:
        for raw_id, line in rows:
            text = line.decode("utf-8", errors="replace")
            conn.execute(
                INSERT_STAGED_WITH_ID,
                (raw_id, mode, f"test:{raw_id}", text, sha256_hex(text.encode("utf-8"))),
            )


def promoter(pg: Cluster, dbname: str, limits: PromotionLimits | None = None) -> Promoter:
    return Promoter(role_engine(pg, dbname, "intel_svc"), load_phase_rules(), limits)


def projection(pg: Cluster, dbname: str) -> dict[str, list[tuple[Any, ...]]]:
    """Every P4-written row, canonicalized: identifiers included, created_at excluded."""
    queries = {
        "sessions": "SELECT id::text, source_type::text, cowrie_session_id, host(src_ip), "
        "src_port, first_event_at, first_raw_record_id FROM intel.attack_session ORDER BY id",
        "events": "SELECT id::text, session_id::text, raw_record_id, seq, event_type::text, "
        "occurred_at, raw_text, normalized_text, truncated, username, attempted_secret, "
        "artifact_sha256 FROM intel.attack_event ORDER BY session_id, seq",
        "behaviors": "SELECT id::text, session_id::text, ordinal, phase::text, "
        "phase_rules_version, started_at, ended_at FROM intel.attacker_behavior "
        "ORDER BY session_id, ordinal",
        "links": "SELECT behavior_id::text, event_id::text, session_id::text "
        "FROM intel.behavior_event ORDER BY behavior_id, event_id",
        "quarantine": "SELECT stage::text, reason_code, raw_record_id, payload "
        "FROM intel_raw.quarantine_record WHERE stage = 'promotion' "
        "ORDER BY raw_record_id, reason_code",
    }
    with pg.admin(dbname) as conn:
        return {
            name: [tuple(r) for r in conn.execute(sql).fetchall()] for name, sql in queries.items()
        }
