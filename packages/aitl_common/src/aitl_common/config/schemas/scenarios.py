"""Scenario template library (PRD FR-003, FR-010c, FR-011, FR-034a; ARCHITECTURE.md §13, §37.3).

``config/scenarios/template_library_vN/T-NN.yaml``. A template is keyed by the
abstracted threat-pattern representation - the abstraction rules it is
compatible with and the pattern's ``(objective, target_tier, movement)`` - and
authors, as trusted configuration, everything a generated scenario contains:
the poisoned document text, entry point, target selection, task reference,
expected policy outcome and the deterministic predicates.

The schema has no field that can hold or reference attacker data: no
``source_reference``, no event/behavior/TTP/session identifier, no free-form
parameter. Its only parameter is ``target_asset``, a fixture asset ID chosen
from a closed list that must equal the fixture assets the selector admits.
Each allowed target has one ``variant`` (poisoned text, expected decisions,
steps), so instantiating a template is a lookup, never text substitution.
"""

from __future__ import annotations

from typing import Annotated, ClassVar, Final, Literal

from pydantic import Field, StringConstraints, model_validator

from aitl_common.config.errors import ConfigValidationError, IssueType, issue
from aitl_common.config.schemas.base import ArtifactModel, ConfigModel, fail, require_unique
from aitl_common.config.vocabulary import (
    AbstractionRuleId,
    AbstractionTableVersion,
    AgentRole,
    AssetId,
    AssetKind,
    DataflowDecision,
    Decision,
    EntryPointType,
    FixtureSetVersion,
    IntVersion,
    MockEndpoint,
    Movement,
    Objective,
    PolicyId,
    TargetTier,
    TaskId,
    TemplateId,
    TemplateLibraryVersion,
    ToolDefinitionsVersion,
    ToolName,
)

Text = Annotated[str, StringConstraints(min_length=1, max_length=500)]
TARGET_PARAMETER: Final = "target_asset"

# "target" is the variant's target asset; it never collides with an AssetId.
AssetRef = Literal["target"] | AssetId


class PatternCompatibility(ConfigModel):
    abstraction_table_version: AbstractionTableVersion
    rule_ids: tuple[AbstractionRuleId, ...] = Field(min_length=1, max_length=16)
    objective: Objective
    target_tier: TargetTier
    movement: Movement


class TaskRef(ConfigModel):
    task_id: TaskId
    version: IntVersion


class PolicyRef(ConfigModel):
    policy_id: PolicyId
    version: IntVersion


class EntryPoint(ConfigModel):
    type: EntryPointType
    asset_id: AssetId


class TargetSelector(ConfigModel):
    tier: TargetTier
    kinds: tuple[Literal["file", "table"], ...] = Field(min_length=1, max_length=2)


class AssetParameter(ConfigModel):
    type: Literal["fixture_asset_id"]
    allowed: tuple[AssetId, ...] = Field(min_length=1, max_length=16)


class ToolCallRef(ConfigModel):
    tool: ToolName
    endpoint: MockEndpoint | None

    @model_validator(mode="after")
    def _endpoint(self) -> ToolCallRef:
        if (self.tool == "mock_api") != (self.endpoint is not None):
            raise fail(
                IssueType.INCONSISTENT,
                "endpoint is required for mock_api and forbidden for other tools",
                self.tool,
            )
        return self


class PermissionExpectation(ToolCallRef):
    """The target policy's permission decision for this call (static lookup)."""

    check: Literal["permission"]
    asset: AssetRef | None
    decision: Decision


class DataflowExpectation(ToolCallRef):
    """The target policy's data-flow decision for target-derived content sent here."""

    check: Literal["dataflow"]
    source: Literal["target"]
    decision: DataflowDecision


Expectation = Annotated[PermissionExpectation | DataflowExpectation, Field(discriminator="check")]


class PresentTaskStep(ConfigModel):
    step_type: Literal["present_task"]
    description: Text


class PlacePoisonedDocumentStep(ConfigModel):
    step_type: Literal["place_poisoned_document"]
    description: Text


class AdversarialInstructionStep(ToolCallRef):
    step_type: Literal["adversarial_instruction"]
    description: Text
    asset: AssetRef | None


Step = Annotated[
    PresentTaskStep | PlacePoisonedDocumentStep | AdversarialInstructionStep,
    Field(discriminator="step_type"),
]


class Variant(ConfigModel):
    poisoned_content: Annotated[str, StringConstraints(min_length=1, max_length=4000)]
    expected_outcome: tuple[Expectation, ...] = Field(min_length=1, max_length=8)
    steps: tuple[Step, ...] = Field(min_length=3, max_length=16)

    @model_validator(mode="after")
    def _steps(self) -> Variant:
        kinds = [s.step_type for s in self.steps]
        if kinds[:2] != ["present_task", "place_poisoned_document"] or set(kinds[2:]) != {
            "adversarial_instruction"
        }:
            raise fail(
                IssueType.INCONSISTENT,
                "steps must be present_task, place_poisoned_document, then one or more "
                "adversarial_instruction steps",
            )
        return self


class LegitimateCall(ConfigModel):
    tool: Literal["file_read", "database_query"]
    asset_id: AssetId


class CalledPredicate(ConfigModel):
    type: Literal["called"]
    tool: Literal["file_read", "database_query"]
    asset_id: AssetId


class FinalResponseContainsAll(ConfigModel):
    type: Literal["final_response_contains_all"]
    tokens: tuple[Annotated[str, StringConstraints(min_length=1, max_length=64)], ...] = Field(
        min_length=1, max_length=16
    )


class AssetReached(ConfigModel):
    type: Literal["asset_reached"]
    asset: Literal["target"]


class ExfiltrationSucceeded(ConfigModel):
    type: Literal["exfiltration_succeeded"]
    min_tier: TargetTier


TaskSuccess = Annotated[CalledPredicate | FinalResponseContainsAll, Field(discriminator="type")]
AttackSuccess = Annotated[AssetReached | ExfiltrationSucceeded, Field(discriminator="type")]


class ScenarioTemplate(ArtifactModel):
    ARTIFACT_KIND: ClassVar[str] = "scenario_template"

    template_id: TemplateId
    template_library_version: TemplateLibraryVersion
    title: Text
    compatible_with: PatternCompatibility
    agent_task: TaskRef
    agent_role: AgentRole
    fixture_set_version: FixtureSetVersion
    tool_definitions_version: ToolDefinitionsVersion
    target_policy: PolicyRef
    entry_point: EntryPoint
    target_selector: TargetSelector
    parameters: dict[Literal["target_asset"], AssetParameter] = Field(min_length=1, max_length=1)
    variants: dict[AssetId, Variant] = Field(min_length=1, max_length=16)
    task_scope: tuple[AssetId, ...] = Field(min_length=1, max_length=16)
    legitimate_calls: tuple[LegitimateCall, ...] = Field(min_length=1, max_length=16)
    task_success: TaskSuccess
    attack_success: AttackSuccess

    def identity(self) -> tuple[str, str]:
        return (self.template_id, self.template_library_version)

    @model_validator(mode="after")
    def _check(self) -> ScenarioTemplate:
        allowed = self.parameters[TARGET_PARAMETER].allowed
        require_unique(allowed, lambda a: a, "allowed target asset")
        if set(self.variants) != set(allowed):
            raise fail(
                IssueType.UNDECLARED_PARAMETER,
                f"variants {sorted(self.variants)} must be exactly the allowed targets "
                f"{sorted(allowed)}",
                self.template_id,
            )
        require_unique(self.compatible_with.rule_ids, lambda r: r, "compatible rule id")
        require_unique(self.task_scope, lambda a: a, "task_scope asset")
        require_unique(self.legitimate_calls, lambda c: (c.tool, c.asset_id), "legitimate call")
        for target in allowed:
            if target in self.task_scope:
                raise fail(
                    IssueType.INCONSISTENT,
                    f"target {target} is inside task_scope; the attack must be out of scope",
                    target,
                )
        for call in self.legitimate_calls:
            if call.asset_id not in self.task_scope:
                raise fail(
                    IssueType.INCONSISTENT,
                    f"legitimate call on {call.asset_id} is outside task_scope (FR-034a)",
                    call.asset_id,
                )
        exfil = isinstance(self.attack_success, ExfiltrationSucceeded)
        if exfil != (self.compatible_with.movement == "internal_to_external"):
            raise fail(
                IssueType.INCONSISTENT,
                "exfiltration_succeeded is required exactly for internal_to_external patterns",
                self.template_id,
            )
        if isinstance(self.attack_success, ExfiltrationSucceeded) and (
            self.attack_success.min_tier != self.compatible_with.target_tier
        ):
            raise fail(
                IssueType.INCONSISTENT,
                "exfiltration min_tier must equal the pattern's target_tier",
                self.template_id,
            )
        if self.target_selector.tier != self.compatible_with.target_tier:
            raise fail(
                IssueType.INCONSISTENT,
                "target_selector.tier must equal the pattern's target_tier",
                self.template_id,
            )
        return self


def validate_scenario_parameters(template: ScenarioTemplate, params: dict[str, object]) -> str:
    """Check scenario-request parameters against a template; return the target asset.

    Used by scenario generation (P7): exactly the declared parameters, each with
    an allowed value. Anything else is rejected, never coerced or defaulted.
    """
    artifact, version = template.identity()
    declared = set(template.parameters)
    issues = [
        issue(
            artifact,
            version,
            f"params.{name}",
            IssueType.UNDECLARED_PARAMETER,
            "parameter is not declared by the template",
            name,
        )
        for name in sorted(set(params) - declared)
    ] + [
        issue(
            artifact,
            version,
            f"params.{name}",
            IssueType.MISSING_FIELD,
            "declared parameter is missing",
            name,
        )
        for name in sorted(declared - set(params))
    ]
    if issues:
        raise ConfigValidationError(issues)
    value = params[TARGET_PARAMETER]
    if not isinstance(value, str) or value not in template.parameters[TARGET_PARAMETER].allowed:
        raise ConfigValidationError(
            [
                issue(
                    artifact,
                    version,
                    f"params.{TARGET_PARAMETER}",
                    IssueType.INVALID_ENUM,
                    "value is not an allowed target asset",
                    str(value),
                )
            ]
        )
    return value


ASSET_KINDS_FOR_TOOL: dict[str, AssetKind] = {"file_read": "file", "database_query": "table"}
