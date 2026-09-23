"""intel_raw staging for the Log Shipper, against real PostgreSQL (P3; FR-004b, FR-005, FR-048).

- ``ingest_writer`` needs nothing beyond INSERT: replay-safe ingestion uses an
  untargeted ``ON CONFLICT DO NOTHING`` against the idempotency indexes of
  migration 0014, which requires no SELECT privilege.
- Re-ingesting an identical event (same ingest mode, same payload hash) or an
  identical shipper-stage quarantine record inserts nothing; nothing is ever
  updated or deleted (FR-044).
- Everything that would need more privilege than INSERT is denied.
"""

from __future__ import annotations

from collections.abc import Iterator

import psycopg
import pytest

from tests.pg_harness import Cluster

INSERT_EVENT = (
    "INSERT INTO intel_raw.raw_ingest_record "
    "(kind, ingest_mode, source_ref, payload, payload_sha256) "
    "VALUES (%s, %s, %s, %s, %s) ON CONFLICT DO NOTHING"
)
INSERT_QUARANTINE = (
    "INSERT INTO intel_raw.quarantine_record (stage, reason_code, payload) "
    "VALUES (%s, %s, %s) ON CONFLICT DO NOTHING"
)
SHA_A = "a" * 64
SHA_B = "b" * 64


@pytest.fixture
def staging_db(pg: Cluster, fresh_db: str) -> str:
    pg.upgrade(fresh_db)
    return fresh_db


@pytest.fixture
def writer(pg: Cluster, staging_db: str) -> Iterator[psycopg.Connection[tuple[object, ...]]]:
    with pg.connect(staging_db, "ingest_writer") as conn:
        conn.autocommit = True
        yield conn


def _count(pg: Cluster, db: str, table: str) -> int:
    with pg.admin(db) as conn:
        row = conn.execute(f"SELECT count(*) FROM intel_raw.{table}").fetchone()
    assert row is not None
    return int(str(row[0]))


def test_identical_event_is_stored_once(
    pg: Cluster, staging_db: str, writer: psycopg.Connection[tuple[object, ...]]
) -> None:
    first = writer.execute(INSERT_EVENT, ("event", "fixture", "a.json:0", "{}", SHA_A))
    again = writer.execute(INSERT_EVENT, ("event", "fixture", "a.json:0", "{}", SHA_A))
    moved = writer.execute(INSERT_EVENT, ("event", "fixture", "b.json:9", "{}", SHA_A))
    assert (first.rowcount, again.rowcount, moved.rowcount) == (1, 0, 0)
    assert _count(pg, staging_db, "raw_ingest_record") == 1


def test_dedupe_is_per_ingest_mode_and_payload(
    pg: Cluster, staging_db: str, writer: psycopg.Connection[tuple[object, ...]]
) -> None:
    writer.execute(INSERT_EVENT, ("event", "fixture", "a:0", "{}", SHA_A))
    writer.execute(INSERT_EVENT, ("event", "live", "a:0", "{}", SHA_A))
    writer.execute(INSERT_EVENT, ("event", "fixture", "a:1", "{}", SHA_B))
    assert _count(pg, staging_db, "raw_ingest_record") == 3


def test_heartbeats_are_never_deduplicated(
    pg: Cluster, staging_db: str, writer: psycopg.Connection[tuple[object, ...]]
) -> None:
    for _ in range(3):
        writer.execute(INSERT_EVENT, ("heartbeat", "fixture", "heartbeat", "{}", SHA_A))
    assert _count(pg, staging_db, "raw_ingest_record") == 3


def test_identical_shipper_quarantine_is_stored_once(
    pg: Cluster, staging_db: str, writer: psycopg.Connection[tuple[object, ...]]
) -> None:
    writer.execute(INSERT_QUARANTINE, ("shipper_parse", "json.invalid", '{"x":1}'))
    writer.execute(INSERT_QUARANTINE, ("shipper_parse", "json.invalid", '{"x":1}'))
    writer.execute(INSERT_QUARANTINE, ("shipper_parse", "json.invalid", '{"x":2}'))
    writer.execute(INSERT_QUARANTINE, ("shipper_validate", "json.invalid", '{"x":1}'))
    assert _count(pg, staging_db, "quarantine_record") == 3


def test_promotion_quarantine_is_not_constrained_by_the_shipper_key(
    pg: Cluster, staging_db: str
) -> None:
    """The dedupe key covers shipper-stage rows (raw_record_id NULL) only."""
    with pg.connect(staging_db, "ingest_writer") as conn:
        conn.execute(INSERT_EVENT, ("event", "fixture", "a:0", "{}", SHA_A))
        conn.commit()
    with pg.connect(staging_db, "intel_svc") as conn:
        raw_id = conn.execute("SELECT id FROM intel_raw.raw_ingest_record").fetchone()
        assert raw_id is not None
        for _ in range(2):
            conn.execute(
                "INSERT INTO intel_raw.quarantine_record (raw_record_id, stage, reason_code, "
                "payload) VALUES (%s, 'promotion', 'x', 'p')",
                (raw_id[0],),
            )
        conn.commit()
    assert _count(pg, staging_db, "quarantine_record") == 2


@pytest.mark.parametrize(
    "statement",
    [
        "SELECT count(*) FROM intel_raw.raw_ingest_record",
        "SELECT count(*) FROM intel_raw.quarantine_record",
        "UPDATE intel_raw.raw_ingest_record SET source_ref = 'x'",
        "DELETE FROM intel_raw.raw_ingest_record",
        "TRUNCATE intel_raw.raw_ingest_record",
        "SELECT count(*) FROM intel.attack_session",
        "SELECT count(*) FROM agent.data_asset",
        "SELECT count(*) FROM security.policy",
        "INSERT INTO intel.attack_session (id, source_type, cowrie_session_id, src_ip, "
        "src_port, first_event_at, first_raw_record_id) VALUES (gen_random_uuid(), "
        "'honeypot', 'x', '192.0.2.1', 1, now(), 1)",
        # RETURNING and targeted conflict handling both need SELECT, which the role lacks.
        "INSERT INTO intel_raw.raw_ingest_record (kind, ingest_mode, source_ref, payload, "
        "payload_sha256) VALUES ('event', 'fixture', 'r', 'p', repeat('c', 64)) RETURNING id",
        "INSERT INTO intel_raw.raw_ingest_record (kind, ingest_mode, source_ref, payload, "
        "payload_sha256) VALUES ('event', 'fixture', 'r', 'p', repeat('c', 64)) "
        "ON CONFLICT (ingest_mode, payload_sha256) WHERE kind = 'event' DO NOTHING",
    ],
)
def test_ingest_writer_has_no_privilege_beyond_insert(
    writer: psycopg.Connection[tuple[object, ...]], statement: str
) -> None:
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        writer.execute(statement)


def test_owner_cannot_rewrite_staged_telemetry(pg: Cluster, staging_db: str) -> None:
    """Append-only holds even for the owner: dedupe never mutates history."""
    with pg.connect(staging_db, "ingest_writer") as conn:
        conn.execute(INSERT_EVENT, ("event", "fixture", "a:0", "{}", SHA_A))
        conn.commit()
    with pg.admin(staging_db) as conn:
        conn.execute("SET ROLE aitl_owner")
        with pytest.raises(psycopg.Error) as caught:
            conn.execute("UPDATE intel_raw.raw_ingest_record SET payload = 'x'")
    assert caught.value.sqlstate == "AITL1"  # append-only trigger (P1)
