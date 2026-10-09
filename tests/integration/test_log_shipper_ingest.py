"""Log Shipper end to end against real PostgreSQL (P3; FR-004b, FR-005, FR-005b, FR-013, FR-048).

The real shipper (reader -> parser -> quota -> StagingWriter as ingest_writer)
ingests the synthetic corpus into a migrated database:

- every corpus line is staged or quarantined with the expected reason;
- staged payloads are the lines verbatim (invalid UTF-8 replaced, FR-013);
- ``ingest_mode`` comes from configuration only, never from content;
- ingestion is deterministic across fresh databases and replay-safe in one;
- a database outage loses nothing; logs never carry telemetry content.
"""

from __future__ import annotations

import json
import logging
import shutil
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine

from aitl_common.db.engine import DatabaseSettings, create_role_engine
from aitl_common.logging import JsonFormatter
from log_shipper.config import ShipperSettings
from log_shipper.records import EventRecord, QuarantineRecord
from log_shipper.service import Shipper
from log_shipper.writer import StagingWriter, WriteResult
from tests.fixtures import honeypot_corpus
from tests.pg_harness import Cluster

Rows = list[tuple[Any, ...]]


def _engine(pg: Cluster, dbname: str, role: str = "ingest_writer") -> Engine:
    settings = DatabaseSettings(
        host=pg.host, port=pg.port, dbname=dbname, user=role, password=pg.passwords[role]
    )
    return create_role_engine(role, settings)


def _shipper(
    tmp_path: Path, writer: Any, *, mode: str = "fixture", source: Path | None = None
) -> Shipper:
    state = tmp_path / f"state-{len(list(tmp_path.glob('state-*')))}"
    state.mkdir()
    if source is None:
        source = tmp_path / "corpus"
        if not source.exists():
            shutil.copytree(honeypot_corpus.CORPUS_DIR, source)
    settings = ShipperSettings.from_env(
        {"SHIPPER_MODE": mode, "SHIPPER_SOURCE_DIR": str(source), "SHIPPER_STATE_DIR": str(state)}
    )
    return Shipper(settings, writer, sleep=lambda _: None)


def _drain(shipper: Shipper) -> None:
    for _ in range(1000):
        if not shipper.run_cycle():
            return
    raise AssertionError("shipper did not drain the corpus")


def _events(pg: Cluster, dbname: str) -> Rows:
    with pg.admin(dbname) as conn:
        return conn.execute(
            "SELECT kind, ingest_mode, source_ref, payload, payload_sha256 "
            "FROM intel_raw.raw_ingest_record WHERE kind = 'event' ORDER BY source_ref"
        ).fetchall()


def _quarantine(pg: Cluster, dbname: str) -> Rows:
    with pg.admin(dbname) as conn:
        return conn.execute(
            "SELECT stage, reason_code, payload, raw_record_id FROM intel_raw.quarantine_record "
            "ORDER BY reason_code, payload"
        ).fetchall()


@pytest.fixture
def staging_db(pg: Cluster, fresh_db: str) -> str:
    pg.upgrade(fresh_db)
    return fresh_db


@pytest.fixture
def writer(pg: Cluster, staging_db: str) -> Iterator[StagingWriter]:
    engine = _engine(pg, staging_db)
    yield StagingWriter(engine)
    engine.dispose()


def test_committed_corpus_equals_generator() -> None:
    rendered = honeypot_corpus.render()
    committed = {p.name for p in honeypot_corpus.CORPUS_DIR.iterdir()}
    assert committed == set(rendered)
    for name, content in rendered.items():
        assert (honeypot_corpus.CORPUS_DIR / name).read_bytes() == content, name


def test_corpus_stages_and_quarantines_as_expected(
    pg: Cluster, staging_db: str, writer: StagingWriter, tmp_path: Path
) -> None:
    _drain(_shipper(tmp_path, writer))
    events = _events(pg, staging_db)
    quarantine = _quarantine(pg, staging_db)
    for name, (staged, reasons) in honeypot_corpus.expected().items():
        assert sum(1 for e in events if e[2].split(":")[0] == name) == staged, name
        got = sorted(
            q[1] for q in quarantine if json.loads(q[2])["source_ref"].split(":")[0] == name
        )
        assert got == reasons, name
    assert {e[1] for e in events} == {"fixture"}
    assert {q[0] for q in quarantine} <= {"shipper_parse", "shipper_validate"}
    assert all(q[3] is None for q in quarantine)


def test_staged_payloads_are_verbatim_lines(
    pg: Cluster, staging_db: str, writer: StagingWriter, tmp_path: Path
) -> None:
    _drain(_shipper(tmp_path, writer))
    by_ref = {e[2]: e[3] for e in _events(pg, staging_db)}
    for name, content in honeypot_corpus.render().items():
        offset = 0
        for line in content.split(b"\n")[:-1]:
            ref = f"{name}:{offset}"
            if ref in by_ref:
                assert by_ref[ref] == line.decode("utf-8", errors="replace")
            offset += len(line) + 1
    hostile = [p for p in by_ref.values() if "DROP TABLE" in p]
    assert hostile  # stored as inert text, and the table is still there
    assert "\ufffd" in "".join(by_ref.values())  # invalid UTF-8 replaced, not dropped


def test_content_cannot_choose_ingest_mode_or_kind(
    pg: Cluster, staging_db: str, writer: StagingWriter, tmp_path: Path
) -> None:
    _drain(_shipper(tmp_path, writer))
    spoofed = [e for e in _events(pg, staging_db) if '"source_type": "honeypot"' in e[3]]
    assert len(spoofed) == 1
    assert spoofed[0][:2] == ("event", "fixture")


def test_live_mode_labels_live(
    pg: Cluster, staging_db: str, writer: StagingWriter, tmp_path: Path
) -> None:
    logs = tmp_path / "cowrie-logs"
    logs.mkdir()
    (logs / "cowrie.json").write_bytes(honeypot_corpus.render()["ar1_cloud_credentials.json"])
    _drain(_shipper(tmp_path, writer, mode="live", source=logs))
    events = _events(pg, staging_db)
    assert len(events) == honeypot_corpus.expected()["ar1_cloud_credentials.json"][0]
    assert {e[1] for e in events} == {"live"}


def test_ingestion_is_deterministic_across_fresh_databases(
    pg: Cluster, staging_db: str, writer: StagingWriter, tmp_path: Path
) -> None:
    _drain(_shipper(tmp_path, writer))
    other = f"{staging_db}_b"
    pg.create_database(other)
    try:
        pg.upgrade(other)
        engine = _engine(pg, other)
        try:
            _drain(_shipper(tmp_path, StagingWriter(engine)))
        finally:
            engine.dispose()
        assert _events(pg, staging_db) == _events(pg, other)
        assert _quarantine(pg, staging_db) == _quarantine(pg, other)
    finally:
        pg.drop_database(other)


def test_replay_into_the_same_database_adds_nothing(
    pg: Cluster, staging_db: str, writer: StagingWriter, tmp_path: Path
) -> None:
    _drain(_shipper(tmp_path, writer))
    events, quarantine = _events(pg, staging_db), _quarantine(pg, staging_db)
    # A second shipper with empty position state re-reads everything.
    replay = _shipper(tmp_path, writer)
    _drain(replay)
    assert _events(pg, staging_db) == events
    assert _quarantine(pg, staging_db) == quarantine
    assert replay.counters.shipped == 0


class _FlakyWriter:
    """The real writer behind an outage that fails the first ``failures`` writes."""

    def __init__(self, inner: StagingWriter, failures: int) -> None:
        self.inner, self.failures = inner, failures

    def write(
        self, events: Sequence[EventRecord], quarantine: Sequence[QuarantineRecord]
    ) -> WriteResult:
        if self.failures:
            self.failures -= 1
            raise ConnectionError("database unavailable")
        return self.inner.write(events, quarantine)


def test_database_outage_loses_nothing(
    pg: Cluster, staging_db: str, writer: StagingWriter, tmp_path: Path
) -> None:
    shipper = _shipper(tmp_path, _FlakyWriter(writer, failures=3))
    for _ in range(3):
        with pytest.raises(ConnectionError):
            shipper.run_cycle()
    assert _events(pg, staging_db) == []
    _drain(shipper)
    expected = sum(staged for staged, _ in honeypot_corpus.expected().values())
    assert len(_events(pg, staging_db)) == expected


def test_heartbeat_is_staged_as_heartbeat(
    pg: Cluster, staging_db: str, writer: StagingWriter, tmp_path: Path
) -> None:
    shipper = _shipper(tmp_path, writer)
    _drain(shipper)
    shipper.heartbeat(pending=False)
    with pg.admin(staging_db) as conn:
        rows = conn.execute(
            "SELECT ingest_mode, payload FROM intel_raw.raw_ingest_record WHERE kind = 'heartbeat'"
        ).fetchall()
    assert len(rows) == 1
    assert rows[0][0] == "fixture"
    assert set(json.loads(str(rows[0][1]))["counters"]) >= {"shipped", "quarantined", "dropped"}


def test_writer_refuses_any_role_but_ingest_writer(pg: Cluster, staging_db: str) -> None:
    engine = _engine(pg, staging_db, role="intel_svc")
    try:
        with pytest.raises(PermissionError):
            StagingWriter(engine)
    finally:
        engine.dispose()


def test_logs_never_carry_telemetry_content(
    staging_db: str, writer: StagingWriter, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """SEC-009: passwords, commands, addresses and sessions never reach service logs."""
    shipper = _shipper(tmp_path, writer)
    with caplog.at_level(logging.DEBUG):
        _drain(shipper)
        shipper.heartbeat(pending=False)
    rendered = "\n".join(JsonFormatter().format(r) for r in caplog.records)
    assert "shipper" in rendered
    for forbidden in ("toor", "letmein", "qwerty", "DROP TABLE", "id_rsa", "203.0.113", "a2b0c0"):
        assert forbidden not in rendered, forbidden
