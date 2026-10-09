"""Deterministic event ordering and behavior reconstruction (FR-006; ADR-024 D1, D4).

Pure functions: no database, no clock, no randomness, no I/O.

**Ordering (D1).** A session's events are ordered by ``(occurred_at ASC,
raw_record_id ASC)`` and numbered ``seq = 1..n``. ``raw_record_id`` is the
immutable P3 staging identity (append-only ``intel_raw``), so ties never
depend on attacker text, on the order rows are read or inserted, or on file
order.

**Phases (FR-006).** Each event is matched against every rule of the
versioned phase-rule artifact (P2), using the match semantics fixed in
``aitl_common.config.schemas.intel``: event-type rules on ``event_type``;
command rules on the whitespace tokens of the *normalized* text of
``command_input`` events, by exact token equality or ``str.startswith`` only.
Every matching rule contributes, so an event may belong to several phases;
an event no rule matches belongs to ``unclassified``.

**Behaviors (D4).** One ``AttackerBehavior`` per distinct phase in the
session. Ordinals follow each phase's first event ``seq``; phases first
seen at the same ``seq`` are ordered by the fixed ``behavior_phase`` enum
order. ``started_at``/``ended_at`` are the earliest and latest timestamps of
the phase's events. Every event is linked to at least one behavior.

Nothing here assigns ATT&CK techniques, TTPs, intent, or success.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Final, get_args

from aitl_common.config.schemas.intel import (
    CommandArgumentMatch,
    CommandMatch,
    CommandPrefixMatch,
    EventTypeMatch,
    PhaseRules,
)
from aitl_common.config.vocabulary import BehaviorPhase
from intel_service.events import NormalizedEvent

__all__ = [
    "PHASE_ORDER",
    "UNCLASSIFIED",
    "Behavior",
    "SequencedEvent",
    "order_events",
    "phases_of",
    "reconstruct",
]

# The behavior_phase enum order (vocabulary == database enum, tested).
PHASE_ORDER: Final[tuple[str, ...]] = get_args(BehaviorPhase)
UNCLASSIFIED: Final = "unclassified"


@dataclass(frozen=True, slots=True)
class SequencedEvent:
    seq: int
    event: NormalizedEvent


@dataclass(frozen=True, slots=True)
class Behavior:
    ordinal: int
    phase: str
    started_at: datetime
    ended_at: datetime
    event_seqs: tuple[int, ...]  # ascending


def order_events(events: Iterable[NormalizedEvent]) -> tuple[SequencedEvent, ...]:
    """D1: seq = rank by (occurred_at, raw_record_id), starting at 1."""
    ordered = sorted(events, key=lambda e: (e.occurred_at, e.raw_record_id))
    ids = [e.raw_record_id for e in ordered]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate raw_record_id in one session")
    return tuple(SequencedEvent(seq, event) for seq, event in enumerate(ordered, start=1))


def phases_of(event: NormalizedEvent, rules: PhaseRules) -> tuple[str, ...]:
    """Every phase whose rule matches the event, in enum order; else unclassified."""
    tokens = event.tokens if event.event_type == "command_input" else []
    command = tokens[0] if tokens else None
    matched: set[str] = set()
    for rule in rules.rules:
        match = rule.match
        if isinstance(match, EventTypeMatch):
            hit = event.event_type in match.event_types
        elif command is None:
            hit = False
        elif isinstance(match, CommandMatch):
            hit = command in match.commands
        elif isinstance(match, CommandPrefixMatch):
            hit = any(command.startswith(prefix) for prefix in match.prefixes)
        elif isinstance(match, CommandArgumentMatch):
            hit = command in match.commands and any(
                token.startswith(prefix)
                for token in tokens[1:]
                for prefix in match.argument_prefixes
            )
        else:  # a match kind this version does not know: fail closed
            raise TypeError(f"unsupported phase-rule match {type(match).__name__}")
        if hit:
            matched.add(rule.phase)
    if not matched:
        return (UNCLASSIFIED,)
    return tuple(phase for phase in PHASE_ORDER if phase in matched)


def reconstruct(events: Sequence[SequencedEvent], rules: PhaseRules) -> tuple[Behavior, ...]:
    """D4: one behavior per distinct phase, ordered by first seq then enum order."""
    members: dict[str, list[SequencedEvent]] = {}
    for item in events:
        for phase in phases_of(item.event, rules):
            members.setdefault(phase, []).append(item)
    ranked = sorted(
        members.items(), key=lambda kv: (min(e.seq for e in kv[1]), PHASE_ORDER.index(kv[0]))
    )
    return tuple(
        Behavior(
            ordinal=ordinal,
            phase=phase,
            started_at=min(e.event.occurred_at for e in items),
            ended_at=max(e.event.occurred_at for e in items),
            event_seqs=tuple(sorted(e.seq for e in items)),
        )
        for ordinal, (phase, items) in enumerate(ranked, start=1)
    )
