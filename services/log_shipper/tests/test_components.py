"""Quotas, configuration, records and the service loop (P3; ARCHITECTURE.md §9)."""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from aitl_common.logging import JsonFormatter
from log_shipper.config import LIMITS, ConfigError, ShipperSettings
from log_shipper.health import healthy
from log_shipper.parser import Rejected, parse_line
from log_shipper.quota import RateLimiter, SessionByteQuota
from log_shipper.records import (
    PREVIEW_CHARS,
    EventRecord,
    HeartbeatRecord,
    QuarantineRecord,
    quarantine_record,
)
from log_shipper.service import Shipper
from log_shipper.writer import WriteResult

# --- quotas --------------------------------------------------------------------------


def test_session_quota_admits_then_marks_once_then_drops() -> None:
    quota = SessionByteQuota(limit_bytes=100, max_sessions=10)
    assert [quota.admit("aaaaaaaa", 40) for _ in range(3)] == ["ok", "ok", "first_exceeded"]
    assert quota.admit("aaaaaaaa", 1) == "exceeded"
    assert quota.admit("bbbbbbbb", 40) == "ok"


def test_session_quota_tracks_a_bounded_number_of_sessions() -> None:
    quota = SessionByteQuota(limit_bytes=10, max_sessions=2)
    for session in ("s1", "s2", "s3"):
        quota.admit(session, 10)
    assert len(quota._sessions) == 2


def test_rate_limiter_throttles_and_never_drops() -> None:
    now = [0.0]
    slept: list[float] = []

    def sleep(seconds: float) -> None:
        slept.append(seconds)
        now[0] += seconds

    limiter = RateLimiter(60, clock=lambda: now[0], sleep=sleep)
    assert limiter.acquire(60) == 0.0
    waited = limiter.acquire(30)
    assert waited == pytest.approx(30.0)
    assert sum(slept) == pytest.approx(30.0)


# --- configuration -------------------------------------------------------------------

BASE_ENV = {
    "SHIPPER_MODE": "fixture",
    "SHIPPER_SOURCE_DIR": "/srv/aitl/source",
    "SHIPPER_STATE_DIR": "/srv/aitl/state",
}


def test_settings_defaults() -> None:
    settings = ShipperSettings.from_env(BASE_ENV)
    assert settings.mode == "fixture"
    assert settings.batch_lines == LIMITS["SHIPPER_BATCH_LINES"][0]


@pytest.mark.parametrize(
    "change",
    [
        {"SHIPPER_MODE": None},
        {"SHIPPER_MODE": "honeypot"},
        {"SHIPPER_MODE": "synthetic"},
        {"SHIPPER_MODE": "LIVE"},
        {"SHIPPER_SOURCE_DIR": "relative/dir"},
        {"SHIPPER_SOURCE_DIR": "/srv/../etc"},
        {"SHIPPER_STATE_DIR": "/srv/aitl/source"},
        {"SHIPPER_BATCH_LINES": "0"},
        {"SHIPPER_BATCH_LINES": "100000"},
        {"SHIPPER_BATCH_LINES": "-5"},
        {"SHIPPER_BATCH_LINES": "1e3"},
        {"SHIPPER_BATCH_LINES": " 10"},
        {"SHIPPER_RECORDS_PER_MINUTE": "999999999"},
        {"SHIPPER_SESSION_MAX_BYTES": "1"},
        {"SHIPPER_MAX_BYTES_PER_CYCLE": "100"},
        {"SHIPPER_HEARTBEAT_SECONDS": "١٢"},
    ],
)
def test_settings_fail_closed(change: dict[str, str | None]) -> None:
    env = {**BASE_ENV, **change}
    with pytest.raises(ConfigError):
        ShipperSettings.from_env({k: v for k, v in env.items() if v is not None})


# --- records -------------------------------------------------------------------------


def test_quarantine_payload_is_bounded_escaped_json() -> None:
    raw = b"\x00\x1b[31m" + "‮".encode() + b"x" * 10000 + b"\xff"
    result = parse_line(raw)
    assert isinstance(result, Rejected)
    record = quarantine_record("a.json:0", result)
    document = json.loads(record.payload)
    assert document["reason"] == "line.control_bytes"
    assert document["line_bytes"] == len(raw)
    assert len(document["preview"]) <= PREVIEW_CHARS
    assert document["preview_truncated"] is True
    assert "\x00" not in record.payload
    assert "\x1b" not in record.payload
    assert len(record.payload.encode()) < 65536


# --- service loop --------------------------------------------------------------------

LOGIN = (
    '{"eventid":"cowrie.login.failed","session":"a1b2c3d4e5f6",'
    '"timestamp":"2025-03-01T10:15:30.123456Z","src_ip":"203.0.113.7",'
    '"username":"root","password":"S3cr3t-Attempt-%d"}'
)


class FakeWriter:
    def __init__(self) -> None:
        self.events: list[EventRecord] = []
        self.quarantine: list[QuarantineRecord] = []
        self.heartbeats: list[HeartbeatRecord] = []
        self.fail = False

    def write(
        self, events: Sequence[EventRecord], quarantine: Sequence[QuarantineRecord]
    ) -> WriteResult:
        if self.fail:
            raise ConnectionError("database unavailable")
        new = [e for e in events if e.payload_sha256 not in {x.payload_sha256 for x in self.events}]
        self.events.extend(new)
        self.quarantine.extend(quarantine)
        return WriteResult(len(new), len(events) - len(new), len(quarantine), 0)

    def heartbeat(self, record: HeartbeatRecord) -> None:
        if self.fail:
            raise ConnectionError("database unavailable")
        self.heartbeats.append(record)


def make_shipper(tmp_path: Path, **env: str) -> tuple[Shipper, FakeWriter]:
    source, state = tmp_path / "source", tmp_path / "state"
    source.mkdir(exist_ok=True)
    state.mkdir(exist_ok=True)
    settings = ShipperSettings.from_env(
        {**BASE_ENV, "SHIPPER_SOURCE_DIR": str(source), "SHIPPER_STATE_DIR": str(state), **env}
    )
    writer = FakeWriter()
    return Shipper(settings, writer, sleep=lambda _: None), writer  # type: ignore[arg-type]


def test_every_line_is_staged_quarantined_or_counted(tmp_path: Path) -> None:
    shipper, writer = make_shipper(tmp_path)
    lines = [LOGIN % i for i in range(3)] + ["{bad", '{"eventid":"cowrie.unknown"}']
    (tmp_path / "source" / "s.json").write_text("\n".join(lines) + "\n")
    while shipper.run_cycle():
        pass
    assert len(writer.events) == 3
    assert {e.ingest_mode for e in writer.events} == {"fixture"}
    assert sorted(q.reason_code for q in writer.quarantine) == [
        "event.unknown_eventid",
        "json.invalid",
    ]


def test_mode_comes_only_from_configuration(tmp_path: Path) -> None:
    shipper, writer = make_shipper(tmp_path)
    spoof = LOGIN.replace('"username"', '"ingest_mode":"live","source_type":"honeypot","username"')
    (tmp_path / "source" / "s.json").write_text(spoof % 1 + "\n")
    shipper.run_cycle()
    assert [e.ingest_mode for e in writer.events] == ["fixture"]


def test_database_failure_keeps_positions_and_retries(tmp_path: Path) -> None:
    shipper, writer = make_shipper(tmp_path)
    (tmp_path / "source" / "s.json").write_text(LOGIN % 1 + "\n")
    writer.fail = True
    with pytest.raises(ConnectionError):
        shipper.run_cycle()
    assert writer.events == []
    assert shipper.state.positions == {}
    writer.fail = False
    shipper.run_cycle()
    assert len(writer.events) == 1


def test_run_forever_survives_failures_without_losing_lines(tmp_path: Path) -> None:
    shipper, writer = make_shipper(tmp_path)
    (tmp_path / "source" / "s.json").write_text(LOGIN % 1 + "\n")
    writer.fail = True
    calls = {"n": 0}

    def should_stop() -> bool:
        calls["n"] += 1
        if calls["n"] == 3:
            writer.fail = False
        return calls["n"] > 5

    shipper.run_forever(should_stop)
    assert len(writer.events) == 1


def test_session_quota_drops_and_marks_once(tmp_path: Path) -> None:
    shipper, writer = make_shipper(tmp_path, SHIPPER_SESSION_MAX_BYTES="1024")
    lines = [LOGIN % i for i in range(20)]
    (tmp_path / "source" / "s.json").write_text("\n".join(lines) + "\n")
    while shipper.run_cycle():
        pass
    assert 0 < len(writer.events) < 20
    assert [q.reason_code for q in writer.quarantine] == ["quota.session_bytes"]
    assert shipper.counters.dropped == 20 - len(writer.events)


def test_heartbeat_records_counters_and_health(tmp_path: Path) -> None:
    shipper, writer = make_shipper(tmp_path)
    (tmp_path / "source" / "s.json").write_text(LOGIN % 1 + "\n")
    shipper.run_cycle()
    shipper.heartbeat(pending=False)
    document = json.loads(writer.heartbeats[0].payload)
    assert document["counters"]["shipped"] == 1
    assert document["mode"] == "fixture"
    assert healthy(tmp_path / "state", 60, datetime.now(UTC))
    assert not healthy(tmp_path / "state", 60, datetime.now(UTC) + timedelta(hours=1))
    assert not healthy(tmp_path / "missing", 60, datetime.now(UTC))


def test_logs_never_contain_telemetry_content(tmp_path: Path, caplog: Any) -> None:
    """SEC-009: captured credentials, commands and addresses never reach logs."""
    shipper, _ = make_shipper(tmp_path)
    marker = "S3cr3t-Attempt-"
    (tmp_path / "source" / "s.json").write_text(
        "\n".join([LOGIN % i for i in range(3)] + [f"{{bad {marker}"]) + "\n"
    )
    formatter = JsonFormatter()
    with caplog.at_level(logging.DEBUG, logger="log_shipper"):
        shipper.run_cycle()
        shipper.heartbeat(pending=False)
    rendered = "\n".join(formatter.format(r) for r in caplog.records)
    assert caplog.records
    for forbidden in (marker, "root", "203.0.113.7", "a1b2c3d4e5f6", "bad"):
        assert forbidden not in rendered, forbidden
