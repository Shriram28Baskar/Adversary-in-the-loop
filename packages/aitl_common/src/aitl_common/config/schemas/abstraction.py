"""Adversary abstraction table (PRD FR-010a-FR-010e; ARCHITECTURE.md §12a, §37.2).

Each rule is an ordered sequence of elements that must appear as an ordered,
not necessarily contiguous, subsequence of a session's TTP chain. An element
is a set of alternatives (``[T1552.001, T1552.004]`` = "either"), each a
tactic ID or technique ID; a chain position matches an element when its
tactic or one of its techniques is among the alternatives.

Selection is longest rule, then highest priority, then lowest rule ID
(FR-010b). This table goes further and makes a (length, priority) tie a load
error, so the rule-ID tie-break is never needed to decide a pattern. The
output is controlled vocabulary only; ``rationale`` is trusted text copied
verbatim onto the pattern (FR-010d).
"""

from __future__ import annotations

from typing import Annotated, ClassVar

from pydantic import Field, StringConstraints, model_validator

from aitl_common.config.errors import IssueType
from aitl_common.config.schemas.base import ArtifactModel, ConfigModel, fail, require_unique
from aitl_common.config.vocabulary import (
    AbstractionRuleId,
    AbstractionTableVersion,
    AttackElementId,
    AttackMappingVersion,
    Movement,
    Objective,
    TargetTier,
    ToolCategory,
)

Element = Annotated[tuple[AttackElementId, ...], Field(min_length=1, max_length=16)]


class AbstractionRule(ConfigModel):
    rule_id: AbstractionRuleId
    elements: tuple[Element, ...] = Field(min_length=1, max_length=8)
    objective: Objective
    target_tier: TargetTier
    movement: Movement
    tool_categories: tuple[ToolCategory, ...] = Field(min_length=1, max_length=3)
    priority: Annotated[int, Field(ge=0, le=1000)]
    rationale: Annotated[str, StringConstraints(min_length=1, max_length=500)]

    @model_validator(mode="after")
    def _check(self) -> AbstractionRule:
        for group in self.elements:
            require_unique(group, lambda e: e, f"element alternative in {self.rule_id}")
        require_unique(self.tool_categories, lambda c: c, f"tool category in {self.rule_id}")
        sends = "send" in self.tool_categories
        if sends != (self.movement == "internal_to_external"):
            raise fail(
                IssueType.INCONSISTENT,
                f"{self.rule_id}: tool category 'send' is required exactly when movement is "
                "internal_to_external",
                self.rule_id,
            )
        return self

    def element_ids(self) -> frozenset[str]:
        return frozenset(e for group in self.elements for e in group)


class AbstractionTable(ArtifactModel):
    ARTIFACT_KIND: ClassVar[str] = "abstraction_table"

    version: AbstractionTableVersion
    attack_mapping_version: AttackMappingVersion
    rules: tuple[AbstractionRule, ...] = Field(min_length=1, max_length=128)

    def identity(self) -> tuple[str, str]:
        return ("abstraction_table", self.version)

    @model_validator(mode="after")
    def _check(self) -> AbstractionTable:
        require_unique(self.rules, lambda r: r.rule_id, "abstraction rule id")
        require_unique(
            self.rules,
            lambda r: tuple(tuple(sorted(g)) for g in r.elements),
            "abstraction rule element sequence",
            IssueType.DUPLICATE_RULE,
        )
        require_unique(
            self.rules,
            lambda r: (len(r.elements), r.priority),
            "(length, priority) - selection would fall back to rule ID",
            IssueType.RULE_OVERLAP,
        )
        return self

    def rule(self, rule_id: str) -> AbstractionRule | None:
        return next((r for r in self.rules if r.rule_id == rule_id), None)
