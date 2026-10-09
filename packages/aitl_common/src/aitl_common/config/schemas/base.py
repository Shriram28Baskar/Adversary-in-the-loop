"""Base model for every configuration artifact schema.

- ``extra="forbid"``: an unknown field anywhere is a validation error, so no
  undeclared behavior (an import path, a command, a URL, a new tool) can be
  smuggled in through a new key.
- ``strict=True``: no type coercion (``"1"`` is not ``1``; ``"yes"`` is not a
  boolean). Artifacts are validated from canonical JSON, where arrays become
  tuples and models are immutable (``frozen=True``).
- Semantic checks raise ``PydanticCustomError`` whose type is an
  ``IssueType`` value, so they surface with a precise machine-readable type.
"""

from __future__ import annotations

from abc import abstractmethod
from collections.abc import Callable, Iterable
from typing import Any, ClassVar, TypeVar

from pydantic import BaseModel, ConfigDict
from pydantic_core import PydanticCustomError

from aitl_common.config.errors import IssueType

__all__ = ["ConfigModel", "fail", "require_unique"]

T = TypeVar("T")


class ConfigModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        str_strip_whitespace=False,
        validate_default=True,
        revalidate_instances="always",
    )


class ArtifactModel(ConfigModel):
    """A top-level artifact: knows its kind and how to report its identity."""

    ARTIFACT_KIND: ClassVar[str]

    @abstractmethod
    def identity(self) -> tuple[str, str]:
        """(artifact id, version string) as reported in errors and registries."""


def fail(error_type: IssueType, message: str, identifier: str | None = None) -> PydanticCustomError:
    context: dict[str, Any] = {"identifier": identifier} if identifier is not None else {}
    return PydanticCustomError(error_type.value, message, context)


def require_unique(
    items: Iterable[T],
    key: Callable[[T], object],
    what: str,
    error_type: IssueType = IssueType.DUPLICATE_ID,
) -> None:
    seen: set[object] = set()
    for item in items:
        value = key(item)
        if value in seen:
            raise fail(error_type, f"duplicate {what}: {value}", str(value))
        seen.add(value)
