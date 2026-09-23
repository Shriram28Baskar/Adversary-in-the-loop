"""Deterministic P4 identifiers (ADR-024 D5)."""

from __future__ import annotations

import subprocess
import sys
import uuid

import pytest

from intel_service import identity
from intel_service.identity import behavior_id, event_id, session_id

SESSION = "a2b0c0d0e0f00001"
# Pinned: a change to a namespace or to the name derivation changes every
# persisted identifier, so it must be a deliberate, reviewed change.
PINNED = {
    "session": "32795a35-ca49-5411-97c8-13168a1e3173",
    "event": "0f15457c-1445-573a-81a4-cdb8c8cf5011",
    "behavior": "489377fa-84a6-5a09-b1cc-0c820559a1a3",
}


def test_identifiers_are_pinned_rfc4122_v5() -> None:
    ids = {
        "session": session_id("synthetic", SESSION),
        "event": event_id("synthetic", SESSION, 1),
        "behavior": behavior_id("synthetic", SESSION, 1),
    }
    assert {k: str(v) for k, v in ids.items()} == PINNED
    assert all(v.version == 5 and v.variant == uuid.RFC_4122 for v in ids.values())


def test_same_input_same_identifier() -> None:
    assert session_id("honeypot", SESSION) == session_id("honeypot", SESSION)
    assert event_id("honeypot", SESSION, 7) == event_id("honeypot", SESSION, 7)
    assert behavior_id("honeypot", SESSION, 3) == behavior_id("honeypot", SESSION, 3)


def test_identifiers_survive_a_process_restart() -> None:
    code = (
        "from intel_service.identity import *; "
        f"print(session_id('synthetic', {SESSION!r}), event_id('synthetic', {SESSION!r}, 1), "
        f"behavior_id('synthetic', {SESSION!r}, 1))"
    )
    fresh = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=True,
        env={"PYTHONHASHSEED": "12345"},  # a different hash seed, too
    ).stdout.split()
    assert fresh == [PINNED["session"], PINNED["event"], PINNED["behavior"]]


@pytest.mark.parametrize(
    ("a", "b"),
    [
        (session_id("synthetic", SESSION), session_id("honeypot", SESSION)),
        (session_id("synthetic", SESSION), session_id("synthetic", "a2b0c0d0e0f00002")),
        (event_id("synthetic", SESSION, 1), event_id("synthetic", SESSION, 2)),
        (event_id("synthetic", SESSION, 1), event_id("honeypot", SESSION, 1)),
        (behavior_id("synthetic", SESSION, 1), behavior_id("synthetic", SESSION, 2)),
        (behavior_id("synthetic", SESSION, 1), behavior_id("synthetic", "b" * 16, 1)),
    ],
)
def test_each_identity_input_changes_the_identifier(a: uuid.UUID, b: uuid.UUID) -> None:
    assert a != b


def test_kinds_never_collide() -> None:
    """Same position, different kind (namespace): different identifiers."""
    namespaces = {identity.SESSION_NAMESPACE, identity.EVENT_NAMESPACE, identity.BEHAVIOR_NAMESPACE}
    assert len(namespaces) == 3
    assert event_id("synthetic", SESSION, 1) != behavior_id("synthetic", SESSION, 1)
