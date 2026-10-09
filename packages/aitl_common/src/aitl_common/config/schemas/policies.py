"""Policy artifacts (PRD FR-021-FR-025, FR-033a; ARCHITECTURE.md §17, §37.6).

``config/policies/<policy_id>_vN.yaml``. A policy is two static rule tables:

- permission rules ``(agent_role, tool, endpoint | *, resource_tier | *) ->
  ALLOW | DENY | APPROVAL``;
- data-flow rules ``(source_tier | *, destination_trust | *) -> ALLOW | DENY``.

Every input to a decision is derived by the Gateway from its own records
(FR-019a); nothing in a policy can reference, or be selected by, anything the
agent sends. ``agent_role`` is always exact - no wildcard role - so a policy can
never grant a role that was not deliberately named.

Load-time rules (ARCHITECTURE.md §17), enforced by the bundle validator over
the finite decision-context space: a rule matching no context is a dead rule;
two rules that tie as the most specific match for some context are an overlap
error. ``baseline-permissive`` must ALLOW every rule and cover every context
(FR-033a). Evaluation itself (``decide``) is the Policy Engine (P8).
"""

from __future__ import annotations

from typing import Annotated, ClassVar, Final

from pydantic import Field, StringConstraints, model_validator

from aitl_common.config.errors import IssueType
from aitl_common.config.schemas.base import ArtifactModel, ConfigModel, fail, require_unique
from aitl_common.config.vocabulary import (
    AgentRole,
    DataflowDecision,
    Decision,
    DestinationTrust,
    IntVersion,
    MockEndpoint,
    PolicyId,
    PolicyRuleId,
    Tier,
    ToolDefinitionsVersion,
    ToolName,
    Wildcard,
)

BASELINE_POLICY_ID: Final = "baseline-permissive"


class PermissionRule(ConfigModel):
    rule_id: PolicyRuleId
    agent_role: AgentRole
    tool: ToolName | Wildcard
    endpoint: MockEndpoint | Wildcard
    resource_tier: Tier | Wildcard
    decision: Decision

    @model_validator(mode="after")
    def _check(self) -> PermissionRule:
        if self.tool == "*" and (self.endpoint != "*"):
            raise fail(
                IssueType.INCONSISTENT, "a wildcard tool requires a wildcard endpoint", self.rule_id
            )
        if self.endpoint != "*" and self.tool != "mock_api":
            raise fail(
                IssueType.INCONSISTENT, "only mock_api rules may name an endpoint", self.rule_id
            )
        return self

    @property
    def specificity(self) -> int:
        return sum(1 for field in (self.tool, self.endpoint, self.resource_tier) if field != "*")

    def matches(self, role: str, tool: str, endpoint: str | None, tier: str | None) -> bool:
        return (
            self.agent_role == role
            and self.tool in ("*", tool)
            and self.endpoint in ("*", endpoint)
            and self.resource_tier in ("*", tier)
        )


class DataflowRule(ConfigModel):
    rule_id: PolicyRuleId
    source_tier: Tier | Wildcard
    destination_trust: DestinationTrust | Wildcard
    decision: DataflowDecision

    @property
    def specificity(self) -> int:
        return sum(1 for field in (self.source_tier, self.destination_trust) if field != "*")

    def matches(self, source_tier: str, destination_trust: str) -> bool:
        return self.source_tier in ("*", source_tier) and self.destination_trust in (
            "*",
            destination_trust,
        )


class Policy(ArtifactModel):
    ARTIFACT_KIND: ClassVar[str] = "policy"

    policy_id: PolicyId
    version: IntVersion
    description: Annotated[str, StringConstraints(min_length=1, max_length=500)]
    tool_definitions_version: ToolDefinitionsVersion
    permission_rules: tuple[PermissionRule, ...] = Field(min_length=1, max_length=256)
    dataflow_rules: tuple[DataflowRule, ...] = Field(min_length=1, max_length=64)

    def identity(self) -> tuple[str, str]:
        return (self.policy_id, str(self.version))

    @model_validator(mode="after")
    def _check(self) -> Policy:
        rules: list[PermissionRule | DataflowRule] = [*self.permission_rules, *self.dataflow_rules]
        require_unique(rules, lambda r: r.rule_id, "policy rule id")
        require_unique(
            self.permission_rules,
            lambda r: (r.agent_role, r.tool, r.endpoint, r.resource_tier),
            "permission rule context",
            IssueType.DUPLICATE_RULE,
        )
        require_unique(
            self.dataflow_rules,
            lambda r: (r.source_tier, r.destination_trust),
            "data-flow rule context",
            IssueType.DUPLICATE_RULE,
        )
        if self.policy_id == BASELINE_POLICY_ID:
            for rule in rules:
                if rule.decision != "ALLOW":
                    raise fail(
                        IssueType.INCONSISTENT,
                        f"{BASELINE_POLICY_ID} must ALLOW everything (FR-033a); "
                        f"rule {rule.rule_id} is {rule.decision}",
                        rule.rule_id,
                    )
        return self
