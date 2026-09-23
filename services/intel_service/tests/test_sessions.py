"""Session planning: connect-owned fields and conflicts (ADR-024 D6), provenance anchors."""

from __future__ import annotations

from typing import Any

import pytest

from aitl_common.config.schemas.intel import PhaseRules
from intel_service import identity
from intel_service.events import NormalizedEvent, normalize_event
from intel_service.sessions import (
    CONFLICTING_FIELD,
    NO_CONNECT_EVENT,
    SessionPlan,
    SessionRejected,
    plan_session,
)
from tests.fixtures.cowrie_events import accepted

S = "a1b2c3d4e5f60001"


def event(raw_id: int, eventid: str, second: int, **fields: Any) -> NormalizedEvent:
    stamp = f"2025-03-01T10:00:{second:02d}.000000Z"
    return normalize_event(
        raw_id, "fixture", accepted(eventid, session=S, timestamp=stamp, **fields)
    )


def session(*extra: NormalizedEvent) -> list[NormalizedEvent]:
    return [
        event(5, "cowrie.session.connect", 1, src_port=51022),
        event(6, "cowrie.command.input", 2, input="uname -a"),
        event(7, "cowrie.session.closed", 3),
        *extra,
    ]


def test_valid_session_plan(phase_rules: PhaseRules) -> None:
    plan = plan_session(session(), phase_rules)
    assert isinstance(plan, SessionPlan)
    assert (plan.src_ip, plan.src_port) == ("203.0.113.7", 51022)
    assert (plan.first_raw_record_id, plan.first_event_at.second) == (5, 1)
    assert plan.id == identity.session_id("synthetic", S)
    assert plan.event_id(1) == identity.event_id("synthetic", S, 1)
    assert plan.phase_rules_version == phase_rules.version


def test_first_event_need_not_be_the_connect_event(phase_rules: PhaseRules) -> None:
    """first_event_at / first_raw_record_id follow seq = 1, whatever its type."""
    early = event(9, "cowrie.client.version", 0)
    plan = plan_session(session(early), phase_rules)
    assert isinstance(plan, SessionPlan)
    assert (plan.first_raw_record_id, plan.first_event_at.second, plan.src_port) == (9, 0, 51022)


def test_missing_connect_event(phase_rules: PhaseRules) -> None:
    assert plan_session(session()[1:], phase_rules) == SessionRejected(NO_CONNECT_EVENT)


@pytest.mark.parametrize(
    "extra",
    [
        event(8, "cowrie.session.connect", 4, src_port=51022),  # identical fields, second event
        event(8, "cowrie.session.connect", 4, src_port=1),  # conflicting session identity
        event(8, "cowrie.command.input", 4, src_ip="198.51.100.5"),  # conflicting src_ip
    ],
    ids=["second-connect", "conflicting-connect", "conflicting-src-ip"],
)
def test_conflicts_reject_the_whole_session(
    phase_rules: PhaseRules, extra: NormalizedEvent
) -> None:
    assert plan_session(session(extra), phase_rules) == SessionRejected(CONFLICTING_FIELD)


def test_equivalent_address_spellings_do_not_conflict(phase_rules: PhaseRules) -> None:
    v6 = [
        event(1, "cowrie.session.connect", 1, src_ip="2001:db8::1"),
        event(2, "cowrie.session.closed", 2, src_ip="2001:0db8:0:0::1"),
    ]
    assert isinstance(plan_session(v6, phase_rules), SessionPlan)


def test_rejection_is_deterministic_regardless_of_input_order(phase_rules: PhaseRules) -> None:
    events = session(event(8, "cowrie.session.connect", 4, src_port=1))
    assert plan_session(events, phase_rules) == plan_session(events[::-1], phase_rules)


def test_events_of_two_sessions_are_a_caller_error(phase_rules: PhaseRules) -> None:
    other = normalize_event(9, "fixture", accepted("cowrie.session.closed", session="f" * 16))
    with pytest.raises(ValueError, match="exactly one session"):
        plan_session([*session(), other], phase_rules)
