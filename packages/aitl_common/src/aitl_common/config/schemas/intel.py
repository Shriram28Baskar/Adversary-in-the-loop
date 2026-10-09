"""Behavior-phase and TTP rule tables (PRD FR-006-FR-008; ARCHITECTURE.md §10, §11).

Both tables are token/prefix matchers over the *normalized* text of events
(whitespace-tokenized; the first token is the command). There is no regular
expression anywhere: matching is exact token equality or ``str.startswith``,
linear in input length (FR-007). Match semantics, fixed here for P4/P5:

- ``event_type``: the event's type is in ``event_types``. Never used for
  ``command_input`` - commands are matched by the token kinds below.
- ``command``: a ``command_input`` event whose first token is in ``commands``.
- ``command_prefix``: a ``command_input`` event whose first token starts with
  one of ``prefixes`` (e.g. ``./`` for executing a dropped binary).
- ``command_with_argument_prefix``: first token in ``commands`` and at least
  one later token starting with one of ``argument_prefixes``.
- ``phase`` (TTP rules only): any behavior of the rule's phase.

Every matching rule contributes (an event may belong to several phases; a
behavior may yield several TTPs). ``unclassified`` is reserved for events no
phase rule matches (FR-006) and can never be a rule's target. Identical match
specifications are duplicates and are rejected.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Annotated, ClassVar, Literal

from pydantic import Field, field_validator, model_validator

from aitl_common.config.errors import IssueType
from aitl_common.config.schemas.base import ArtifactModel, ConfigModel, fail, require_unique
from aitl_common.config.vocabulary import (
    AttackMappingVersion,
    BehaviorPhase,
    EventType,
    PhaseRuleId,
    PhaseRulesVersion,
    Token,
    TtpLabel,
    TtpRuleId,
    TtpRulesVersion,
)

Tokens = Annotated[tuple[Token, ...], Field(min_length=1, max_length=64)]


def _unique_tokens(values: tuple[str, ...], what: str) -> tuple[str, ...]:
    require_unique(values, lambda v: v, what, IssueType.DUPLICATE_RULE)
    return values


class EventTypeMatch(ConfigModel):
    kind: Literal["event_type"]
    event_types: tuple[EventType, ...] = Field(min_length=1, max_length=9)

    @field_validator("event_types")
    @classmethod
    def _no_command_input(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        _unique_tokens(value, "event type")
        if "command_input" in value:
            raise fail(
                IssueType.INVALID_VALUE,
                "command_input events are matched by command tokens, not by event type",
                "command_input",
            )
        return value


class CommandMatch(ConfigModel):
    kind: Literal["command"]
    commands: Tokens

    @field_validator("commands")
    @classmethod
    def _unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique_tokens(value, "command")


class CommandPrefixMatch(ConfigModel):
    kind: Literal["command_prefix"]
    prefixes: Tokens

    @field_validator("prefixes")
    @classmethod
    def _unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique_tokens(value, "command prefix")


class CommandArgumentMatch(ConfigModel):
    kind: Literal["command_with_argument_prefix"]
    commands: Tokens
    argument_prefixes: Tokens

    @field_validator("commands", "argument_prefixes")
    @classmethod
    def _unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique_tokens(value, "token")


class PhaseMatch(ConfigModel):
    kind: Literal["phase"]


CommandMatches = CommandMatch | CommandPrefixMatch | CommandArgumentMatch
PhaseRuleMatch = Annotated[
    EventTypeMatch | CommandMatch | CommandPrefixMatch | CommandArgumentMatch,
    Field(discriminator="kind"),
]
TtpRuleMatch = Annotated[
    PhaseMatch | CommandMatch | CommandPrefixMatch | CommandArgumentMatch,
    Field(discriminator="kind"),
]


def _match_key(match: ConfigModel) -> str:
    # Order-insensitive identity of a match specification (for duplicate checks).
    data = match.model_dump(mode="json")
    return repr(sorted((k, sorted(v) if isinstance(v, list) else v) for k, v in data.items()))


def command_reaches(match: ConfigModel, command: str) -> bool:
    """Whether a phase-rule match can route a command with this first token."""
    if isinstance(match, CommandMatch | CommandArgumentMatch):
        return command in match.commands
    if isinstance(match, CommandPrefixMatch):
        return any(command.startswith(prefix) for prefix in match.prefixes)
    return False


class PhaseRule(ConfigModel):
    rule_id: PhaseRuleId
    phase: BehaviorPhase
    match: PhaseRuleMatch

    @field_validator("phase")
    @classmethod
    def _not_unclassified(cls, value: str) -> str:
        if value == "unclassified":
            raise fail(
                IssueType.INVALID_VALUE,
                "unclassified is reserved for events no rule matches (FR-006)",
                value,
            )
        return value


class PhaseRules(ArtifactModel):
    ARTIFACT_KIND: ClassVar[str] = "phase_rules"

    version: PhaseRulesVersion
    rules: tuple[PhaseRule, ...] = Field(min_length=1, max_length=256)

    def identity(self) -> tuple[str, str]:
        return ("phase_rules", self.version)

    @model_validator(mode="after")
    def _check(self) -> PhaseRules:
        require_unique(self.rules, lambda r: r.rule_id, "phase rule id")
        require_unique(
            self.rules, lambda r: _match_key(r.match), "phase rule match", IssueType.DUPLICATE_RULE
        )
        return self

    @property
    def phases(self) -> frozenset[str]:
        return frozenset(r.phase for r in self.rules)


class TtpRule(ConfigModel):
    rule_id: TtpRuleId
    phase: BehaviorPhase
    match: TtpRuleMatch
    label: TtpLabel
    confidence: Annotated[Decimal, Field(ge=0, le=1, decimal_places=2, strict=False)]

    @field_validator("phase")
    @classmethod
    def _not_unclassified(cls, value: str) -> str:
        if value == "unclassified":
            raise fail(
                IssueType.INVALID_VALUE, "TTP rules never classify unclassified behavior", value
            )
        return value

    @field_validator("confidence")
    @classmethod
    def _canonical(cls, value: Decimal) -> Decimal:
        # 0.9 and 0.90 are the same confidence; store one canonical form (numeric(3,2)).
        return value.quantize(Decimal("0.01"))


class TtpRules(ArtifactModel):
    ARTIFACT_KIND: ClassVar[str] = "ttp_rules"

    version: TtpRulesVersion
    attack_mapping_version: AttackMappingVersion
    phase_rules_version: PhaseRulesVersion
    rules: tuple[TtpRule, ...] = Field(min_length=1, max_length=256)

    def identity(self) -> tuple[str, str]:
        return ("ttp_rules", self.version)

    @model_validator(mode="after")
    def _check(self) -> TtpRules:
        require_unique(self.rules, lambda r: r.rule_id, "TTP rule id")
        require_unique(
            self.rules,
            lambda r: (r.phase, _match_key(r.match), r.label),
            "TTP rule (phase, match, label)",
            IssueType.DUPLICATE_RULE,
        )
        return self
