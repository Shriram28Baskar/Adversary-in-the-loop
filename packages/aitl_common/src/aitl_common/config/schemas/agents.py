"""Agent configurations and scripted-agent plans (PRD FR-001, FR-031; ARCHITECTURE.md §15, §37.5).

- ``config/agents/<agent_id>_vN.yaml``: one ``Agent`` row. ``agent_kind``
  discriminates the LLM configuration (provider + pinned model identifier) from
  the scripted test agent (plans, no model). The system prompt and tool
  definitions are referenced by explicit version and hashed at load time.
  Nothing here can name a class, import path, command, URL or endpoint: the
  provider is a closed enum and the provider base URL is Gateway deployment
  configuration (P11), never agent data.
- ``config/agents/prompts/<prompt_id>_vN.md``: trusted system prompt text,
  hashed byte-for-byte.
- ``config/agents/scripted_plans/T-NN.yaml``: the deterministic plan the
  scripted agent follows for one template, one step list per target variant.
  A step is a tool call (tool, endpoint, structured arguments validated against
  the tool definitions) or the final response. Argument values are literals or
  ``{result_of: <earlier step>}`` - the content that step's call returned.
  ``only_if_allowed`` skips a call unless an earlier call was ALLOWed.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Annotated, ClassVar, Literal

from pydantic import Field, StringConstraints, field_validator, model_validator

from aitl_common.config.errors import IssueType
from aitl_common.config.schemas.base import ArtifactModel, ConfigModel, fail, require_unique
from aitl_common.config.schemas.scenarios import TaskRef
from aitl_common.config.vocabulary import (
    AgentId,
    AgentLoopVersion,
    AgentRole,
    ArgumentName,
    AssetId,
    ColumnName,
    FilterOperator,
    FixtureSetVersion,
    IntVersion,
    MockEndpoint,
    ModelId,
    ModelProvider,
    PromptId,
    StepId,
    TemplateId,
    TemplateLibraryVersion,
    ToolDefinitionsVersion,
    ToolName,
)


class PromptRef(ConfigModel):
    prompt_id: PromptId
    version: IntVersion


class ModelSpec(ConfigModel):
    provider: ModelProvider
    model_id: ModelId


class Generation(ConfigModel):
    temperature: Annotated[Decimal, Field(ge=0, le=1, decimal_places=3, strict=False)]
    max_tokens: Annotated[int, Field(ge=1, le=8192)]

    @field_validator("temperature")
    @classmethod
    def _canonical(cls, value: Decimal) -> Decimal:
        return value.quantize(Decimal("0.001"))  # numeric(4,3)


class Limits(ConfigModel):
    max_steps: Annotated[int, Field(ge=1, le=100)]
    model_call_budget: Annotated[int, Field(ge=1, le=200)]
    timeout_seconds: Annotated[int, Field(ge=1, le=3600)]


class PlanRef(ConfigModel):
    template_id: TemplateId
    version: IntVersion


class _AgentBase(ArtifactModel):
    ARTIFACT_KIND: ClassVar[str] = "agent_config"

    agent_id: AgentId
    version: IntVersion
    role: AgentRole
    generation: Generation
    system_prompt: PromptRef
    tool_definitions_version: ToolDefinitionsVersion
    agent_loop_version: AgentLoopVersion
    limits: Limits

    def identity(self) -> tuple[str, str]:
        return (self.agent_id, str(self.version))


class LlmAgentConfig(_AgentBase):
    agent_kind: Literal["llm"]
    model: ModelSpec


class ScriptedAgentConfig(_AgentBase):
    agent_kind: Literal["scripted"]
    scripted_plans: tuple[PlanRef, ...] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def _check(self) -> ScriptedAgentConfig:
        require_unique(self.scripted_plans, lambda p: p.template_id, "scripted plan template")
        return self


AgentConfig = Annotated[LlmAgentConfig | ScriptedAgentConfig, Field(discriminator="agent_kind")]


class FilterValue(ConfigModel):
    column: ColumnName
    op: FilterOperator
    value: Annotated[str, StringConstraints(max_length=256)]


class ResultOf(ConfigModel):
    result_of: StepId


ArgValue = (
    Annotated[str, StringConstraints(max_length=4000)]
    | Annotated[int, Field(ge=0, le=100)]
    | tuple[FilterValue, ...]
    | ResultOf
)


class ToolCallStep(ConfigModel):
    kind: Literal["tool_call"]
    step_id: StepId
    tool: ToolName
    endpoint: MockEndpoint | None
    arguments: dict[ArgumentName, ArgValue] = Field(max_length=8)
    only_if_allowed: StepId | None

    @model_validator(mode="after")
    def _endpoint(self) -> ToolCallStep:
        if (self.tool == "mock_api") != (self.endpoint is not None):
            raise fail(
                IssueType.INCONSISTENT,
                "endpoint is required for mock_api and forbidden for other tools",
                self.step_id,
            )
        return self


class FinalResponseStep(ConfigModel):
    kind: Literal["final_response"]
    step_id: StepId
    text: Annotated[str, StringConstraints(min_length=1, max_length=4000)]


PlanStep = Annotated[ToolCallStep | FinalResponseStep, Field(discriminator="kind")]


class ScriptedPlan(ArtifactModel):
    ARTIFACT_KIND: ClassVar[str] = "scripted_plan"

    template_id: TemplateId
    version: IntVersion
    template_library_version: TemplateLibraryVersion
    agent_task: TaskRef
    fixture_set_version: FixtureSetVersion
    tool_definitions_version: ToolDefinitionsVersion
    variants: dict[AssetId, tuple[PlanStep, ...]] = Field(min_length=1, max_length=16)

    def identity(self) -> tuple[str, str]:
        return (f"scripted_plan:{self.template_id}", str(self.version))

    @model_validator(mode="after")
    def _check(self) -> ScriptedPlan:
        for target, steps in self.variants.items():
            if not steps:
                raise fail(IssueType.MISSING_FIELD, f"variant {target} has no steps", target)
            require_unique(steps, lambda s: s.step_id, f"step id in variant {target}")
            finals = [i for i, s in enumerate(steps) if isinstance(s, FinalResponseStep)]
            if finals != [len(steps) - 1]:
                raise fail(
                    IssueType.INCONSISTENT,
                    f"variant {target}: exactly one final_response, as the last step",
                    target,
                )
            earlier: set[str] = set()
            for step in steps:
                if isinstance(step, ToolCallStep):
                    refs = [v.result_of for v in step.arguments.values() if isinstance(v, ResultOf)]
                    if step.only_if_allowed is not None:
                        refs.append(step.only_if_allowed)
                    for ref in refs:
                        if ref not in earlier:
                            raise fail(
                                IssueType.UNKNOWN_REFERENCE,
                                f"step {step.step_id} references {ref!r}, which is not an "
                                "earlier tool call",
                                ref,
                            )
                    earlier.add(step.step_id)
        return self
