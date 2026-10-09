"""Load-time analysis of policy rule tables (ARCHITECTURE.md §17; PRD FR-021, FR-023, FR-025).

The permission decision context is finite: ``(agent_role, tool, endpoint,
resource_tier)`` over the configured roles, the tool definitions (endpoint
``None`` except for ``mock_api``) and the tiers a tool's resource can have
(``None`` for tools without a resource). Data-flow contexts are
``(source_tier, destination_trust)``. That makes three load-time guarantees
checkable exhaustively rather than by sampling:

- **no ties** - for every context, at most one rule is the most specific match
  (exact beats wildcard; specificity = number of non-wildcard fields);
- **no dead rules** - every rule is the winning match for at least one context
  (a rule that can never win is a typo or a shadowed rule);
- **baseline coverage** - ``baseline-permissive`` matches every context.

``winning_permission`` / ``winning_dataflow`` return the single rule that
governs a context (or ``None`` = unmatched = DENY). The validator uses them to
check each scenario template's expected outcome against its target policy. The
Policy Engine (P8) owns ``decide()``: combining permission and data-flow
results over a taint snapshot is not implemented here.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import TypeVar

from aitl_common.config.errors import IssueType
from aitl_common.config.schemas.fixtures import FixtureSetManifest
from aitl_common.config.schemas.policies import (
    BASELINE_POLICY_ID,
    DataflowRule,
    PermissionRule,
    Policy,
)
from aitl_common.config.schemas.tools import FixedAssetResource, ToolDefinitions
from aitl_common.config.vocabulary import TIERS

__all__ = [
    "PermissionContext",
    "RuleProblem",
    "analyze_policy",
    "dataflow_contexts",
    "permission_contexts",
    "winning_dataflow",
    "winning_permission",
]

R = TypeVar("R", PermissionRule, DataflowRule)


@dataclass(frozen=True, slots=True, order=True)
class PermissionContext:
    agent_role: str
    tool: str
    endpoint: str | None
    resource_tier: str | None


@dataclass(frozen=True, slots=True)
class RuleProblem:
    error_type: IssueType
    identifier: str
    message: str


def resource_tiers(
    tools: ToolDefinitions, fixture_sets: Iterable[FixtureSetManifest]
) -> dict[tuple[str, str | None], tuple[str | None, ...]]:
    manifests = list(fixture_sets)
    tiers: dict[tuple[str, str | None], tuple[str | None, ...]] = {}
    for key, spec in tools.entries().items():
        if spec.resource.kind == "none":
            tiers[key] = (None,)
        elif isinstance(spec.resource, FixedAssetResource):
            locator = spec.resource.locator
            found = {
                a.tier
                for m in manifests
                for a in m.assets
                if a.kind == spec.resource.asset_kind and a.locator == locator
            }
            tiers[key] = tuple(sorted(found, key=TIERS.index))
        else:
            tiers[key] = tuple(TIERS)
    return tiers


def permission_contexts(
    roles: Iterable[str],
    tools: ToolDefinitions,
    fixture_sets: Iterable[FixtureSetManifest],
) -> list[PermissionContext]:
    tiers = resource_tiers(tools, fixture_sets)
    return sorted(
        PermissionContext(role, tool, endpoint, tier)
        for role in sorted(set(roles))
        for (tool, endpoint), tool_tiers in tiers.items()
        for tier in tool_tiers
    )


def dataflow_contexts() -> list[tuple[str, str]]:
    return [(tier, trust) for tier in TIERS for trust in ("internal", "external")]


def _winners(rules: Sequence[R], matching: list[R]) -> list[R]:
    if not matching:
        return []
    top = max(rule.specificity for rule in matching)
    return [rule for rule in matching if rule.specificity == top]


def winning_permission(policy: Policy, context: PermissionContext) -> PermissionRule | None:
    matching = [
        r
        for r in policy.permission_rules
        if r.matches(context.agent_role, context.tool, context.endpoint, context.resource_tier)
    ]
    winners = _winners(policy.permission_rules, matching)
    if len(winners) > 1:
        raise ValueError(f"tie at {context}: {[w.rule_id for w in winners]}")
    return winners[0] if winners else None


def winning_dataflow(policy: Policy, source_tier: str, trust: str) -> DataflowRule | None:
    matching = [r for r in policy.dataflow_rules if r.matches(source_tier, trust)]
    winners = _winners(policy.dataflow_rules, matching)
    if len(winners) > 1:
        raise ValueError(f"tie at {(source_tier, trust)}: {[w.rule_id for w in winners]}")
    return winners[0] if winners else None


def analyze_policy(
    policy: Policy, contexts: Sequence[PermissionContext], roles: Iterable[str]
) -> list[RuleProblem]:
    """Ties, dead rules, unknown roles and baseline coverage (see module docstring)."""
    problems: list[RuleProblem] = []
    known_roles = set(roles)
    for rule in policy.permission_rules:
        if rule.agent_role not in known_roles:
            problems.append(
                RuleProblem(
                    IssueType.UNKNOWN_REFERENCE,
                    rule.rule_id,
                    f"role {rule.agent_role!r} is not the role of any agent configuration",
                )
            )
    won: set[str] = set()
    for context in contexts:
        matching = [
            r
            for r in policy.permission_rules
            if r.matches(context.agent_role, context.tool, context.endpoint, context.resource_tier)
        ]
        winners = _winners(policy.permission_rules, matching)
        if len(winners) > 1:
            problems.append(
                RuleProblem(
                    IssueType.RULE_OVERLAP,
                    ",".join(sorted(w.rule_id for w in winners)),
                    f"rules tie as the most specific match for {context}",
                )
            )
        elif winners:
            won.add(winners[0].rule_id)
        elif policy.policy_id == BASELINE_POLICY_ID:
            problems.append(
                RuleProblem(
                    IssueType.INCONSISTENT,
                    policy.policy_id,
                    f"{BASELINE_POLICY_ID} must match every context; {context} is unmatched",
                )
            )
    for tier, trust in dataflow_contexts():
        matching_df = [r for r in policy.dataflow_rules if r.matches(tier, trust)]
        winners_df = _winners(policy.dataflow_rules, matching_df)
        if len(winners_df) > 1:
            problems.append(
                RuleProblem(
                    IssueType.RULE_OVERLAP,
                    ",".join(sorted(w.rule_id for w in winners_df)),
                    f"data-flow rules tie for ({tier}, {trust})",
                )
            )
        elif winners_df:
            won.add(winners_df[0].rule_id)
        elif policy.policy_id == BASELINE_POLICY_ID:
            problems.append(
                RuleProblem(
                    IssueType.INCONSISTENT,
                    policy.policy_id,
                    f"{BASELINE_POLICY_ID} must match every data flow; "
                    f"({tier}, {trust}) is unmatched",
                )
            )
    # Rules with an unknown role are already reported; do not double-report them.
    live: list[PermissionRule | DataflowRule] = [
        r for r in policy.permission_rules if r.agent_role in known_roles
    ]
    live.extend(policy.dataflow_rules)
    for live_rule in live:
        if live_rule.rule_id not in won:
            problems.append(
                RuleProblem(
                    IssueType.DEAD_RULE,
                    live_rule.rule_id,
                    "rule is never the governing match for any decision context",
                )
            )
    return problems
