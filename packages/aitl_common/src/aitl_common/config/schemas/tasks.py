"""Legitimate task library (PRD FR-003, FR-034a; ARCHITECTURE.md §37.3).

``config/tasks/TK-N_vM.yaml``: the task prompt (trusted system configuration),
the public document it is about, and the task-fact tokens - fixed strings
embedded in that document whose presence in the final response is the
``final_response_contains_all`` task predicate (a disclosed string-match proxy).
"""

from __future__ import annotations

from typing import Annotated, ClassVar

from pydantic import Field, StringConstraints, model_validator

from aitl_common.config.schemas.base import ArtifactModel, require_unique
from aitl_common.config.vocabulary import FixturePath, FixtureSetVersion, IntVersion, TaskId

TaskFactToken = Annotated[str, StringConstraints(pattern=r"^[A-Z0-9][A-Z0-9-]{3,63}$")]


class AgentTaskDefinition(ArtifactModel):
    ARTIFACT_KIND: ClassVar[str] = "agent_task"

    task_id: TaskId
    version: IntVersion
    fixture_set_version: FixtureSetVersion
    prompt: Annotated[str, StringConstraints(min_length=1, max_length=2000)]
    document_path: FixturePath
    task_fact_tokens: tuple[TaskFactToken, ...] = Field(min_length=1, max_length=16)

    def identity(self) -> tuple[str, str]:
        return (self.task_id, str(self.version))

    @model_validator(mode="after")
    def _check(self) -> AgentTaskDefinition:
        require_unique(self.task_fact_tokens, lambda t: t, "task-fact token")
        return self
