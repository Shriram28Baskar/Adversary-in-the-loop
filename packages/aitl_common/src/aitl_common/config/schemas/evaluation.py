"""Evaluation configuration (PRD FR-029a, FR-030; ARCHITECTURE.md §20, §37.7).

``config/eval/eval-vN.yaml``: blast-radius weights and label thresholds -
exactly what ``eval.eval_config`` stores. Per the frozen specification it is
versioned independently of policy and locked per pair (FR-029a); it holds no
policy reference, no repetition count and no predicate. Those live where the
specification puts them: baseline/target policy and N in the replay request
(ARCHITECTURE.md §25), predicates in the scenario templates (FR-034a).
"""

from __future__ import annotations

from typing import Annotated, ClassVar

from pydantic import Field, model_validator

from aitl_common.config.errors import IssueType
from aitl_common.config.schemas.base import ArtifactModel, ConfigModel, fail
from aitl_common.config.vocabulary import BlastRadiusLabel, EvalConfigVersion

Weight = Annotated[int, Field(ge=0, le=1000)]
LABEL_ORDER = ("MINIMAL", "LOW", "MODERATE", "HIGH")


class Weights(ConfigModel):
    R_public: Weight
    R_private: Weight
    R_sensitive: Weight
    U_allowed: Weight
    X_succeeded: Weight


class Threshold(ConfigModel):
    label: BlastRadiusLabel
    min: Annotated[int, Field(ge=0, le=1_000_000)]
    # null only for the top band (">20" in t1).
    max: Annotated[int, Field(ge=0, le=1_000_000)] | None


class EvalConfig(ArtifactModel):
    ARTIFACT_KIND: ClassVar[str] = "eval_config"

    version: EvalConfigVersion
    weights: Weights
    thresholds: tuple[Threshold, ...] = Field(min_length=4, max_length=4)

    def identity(self) -> tuple[str, str]:
        return ("eval_config", self.version)

    @model_validator(mode="after")
    def _check(self) -> EvalConfig:
        labels = tuple(t.label for t in self.thresholds)
        if labels != LABEL_ORDER:
            raise fail(IssueType.INCONSISTENT, f"threshold labels must be {LABEL_ORDER} in order")
        expected_min = 0
        for index, band in enumerate(self.thresholds):
            last = index == len(self.thresholds) - 1
            if band.min != expected_min:
                raise fail(
                    IssueType.INCONSISTENT,
                    f"{band.label} must start at {expected_min} (contiguous from 0)",
                    band.label,
                )
            if last:
                if band.max is not None:
                    raise fail(IssueType.INCONSISTENT, "the top band must be unbounded", band.label)
                break
            if band.max is None or band.max < band.min:
                raise fail(IssueType.INCONSISTENT, f"{band.label} needs max >= min", band.label)
            expected_min = band.max + 1
        return self

    def label_for(self, score: int) -> str:
        for band in self.thresholds:
            if score >= band.min and (band.max is None or score <= band.max):
                return band.label
        raise ValueError(f"score {score} is outside every band")
