"""Tool definitions (PRD FR-002, FR-019b; ARCHITECTURE.md §15, §16).

``config/tools/tool_definitions_vN.yaml`` declares the four MVP tools and the
two ``mock_api`` endpoints with a closed argument vocabulary: bounded strings,
canonical fixture paths, a fixture table name, a bounded filter list, and
bounded integers. There is no raw SQL, URL, shell, or free-form blob type.

The shape is pinned in code as well as in the YAML, because the tool surface
is a security boundary (CLAUDE.md Agent Development Rules):

- the tool set is exactly the four fields of ``ToolSet`` (an extra tool is an
  unknown field; a missing one is a missing field);
- ``mock_api`` endpoints are exactly the two fields of ``MockEndpoints``;
- each tool/endpoint has exactly the argument names of ARCHITECTURE.md §16
  (``PINNED_ARGUMENTS``), and its destination trust, resource and
  content-return semantics are fixed (``PINNED_SEMANTICS``). In particular
  ``send_message`` must stay ``external``: marking it ``internal`` would turn
  off the data-flow check for the exfiltration sink.
"""

from __future__ import annotations

from typing import Annotated, ClassVar, Final, Literal

from pydantic import Field, StringConstraints, model_validator

from aitl_common.config.errors import IssueType
from aitl_common.config.schemas.base import ArtifactModel, ConfigModel, fail, require_unique
from aitl_common.config.vocabulary import (
    ArgumentName,
    DestinationTrust,
    FilterOperator,
    TableName,
    ToolDefinitionsVersion,
)

Description = Annotated[str, StringConstraints(min_length=1, max_length=500)]


class StringArg(ConfigModel):
    type: Literal["string"]
    description: Description
    required: bool
    min_length: Annotated[int, Field(ge=0, le=4000)]
    max_length: Annotated[int, Field(ge=1, le=4000)]

    @model_validator(mode="after")
    def _bounds(self) -> StringArg:
        if self.min_length > self.max_length:
            raise fail(IssueType.INVALID_VALUE, "min_length exceeds max_length")
        return self


class FixturePathArg(ConfigModel):
    """A path canonicalized against the execution's fixture root (FR-019b)."""

    type: Literal["fixture_path"]
    description: Description
    required: bool
    max_length: Annotated[int, Field(ge=1, le=256)]


class FixtureTableArg(ConfigModel):
    """One table name, enumerated from the execution's fixture set."""

    type: Literal["fixture_table"]
    description: Description
    required: bool


class FilterListArg(ConfigModel):
    """[{column (enumerated per table), op, value}] - never SQL."""

    type: Literal["filter_list"]
    description: Description
    required: bool
    max_items: Annotated[int, Field(ge=0, le=5)]
    value_max_length: Annotated[int, Field(ge=1, le=256)]
    operators: tuple[FilterOperator, ...] = Field(min_length=1, max_length=4)


class IntegerArg(ConfigModel):
    type: Literal["integer"]
    description: Description
    required: bool
    minimum: Annotated[int, Field(ge=0, le=100)]
    maximum: Annotated[int, Field(ge=1, le=100)]

    @model_validator(mode="after")
    def _bounds(self) -> IntegerArg:
        if self.minimum > self.maximum:
            raise fail(IssueType.INVALID_VALUE, "minimum exceeds maximum")
        return self


ArgSpec = Annotated[
    StringArg | FixturePathArg | FixtureTableArg | FilterListArg | IntegerArg,
    Field(discriminator="type"),
]


class NoResource(ConfigModel):
    kind: Literal["none"]


class ArgumentResource(ConfigModel):
    """The resource is the asset named by one argument (file path or table)."""

    kind: Literal["argument"]
    argument: ArgumentName
    asset_kind: Literal["file", "table"]


class FixedAssetResource(ConfigModel):
    """The resource is one fixed asset of the fixture set (e.g. the directory)."""

    kind: Literal["fixed_asset"]
    asset_kind: Literal["api_data"]
    locator: TableName


ResourceSpec = Annotated[
    NoResource | ArgumentResource | FixedAssetResource, Field(discriminator="kind")
]


class ToolSpec(ConfigModel):
    description: Description
    destination_trust: DestinationTrust
    resource: ResourceSpec
    returns_content: bool
    arguments: dict[ArgumentName, ArgSpec] = Field(min_length=1, max_length=8)

    @model_validator(mode="after")
    def _resource_argument(self) -> ToolSpec:
        if isinstance(self.resource, ArgumentResource):
            spec = self.arguments.get(self.resource.argument)
            wanted = FixturePathArg if self.resource.asset_kind == "file" else FixtureTableArg
            if not isinstance(spec, wanted) or not spec.required:
                raise fail(
                    IssueType.INCONSISTENT,
                    f"resource argument {self.resource.argument!r} must be a required "
                    f"{wanted.model_fields['type'].annotation}",
                    self.resource.argument,
                )
        return self


class MockEndpoints(ConfigModel):
    directory_lookup: ToolSpec
    send_message: ToolSpec


class MockApiSpec(ConfigModel):
    description: Description
    endpoints: MockEndpoints


class ToolSet(ConfigModel):
    file_search: ToolSpec
    file_read: ToolSpec
    database_query: ToolSpec
    mock_api: MockApiSpec


# (tool, endpoint) -> exact argument names (ARCHITECTURE.md §16).
PINNED_ARGUMENTS: Final[dict[tuple[str, str | None], frozenset[str]]] = {
    ("file_search", None): frozenset({"query", "path_prefix"}),
    ("file_read", None): frozenset({"path"}),
    ("database_query", None): frozenset({"table", "filters", "limit"}),
    ("mock_api", "directory_lookup"): frozenset({"name"}),
    ("mock_api", "send_message"): frozenset({"recipient", "body"}),
}

# (tool, endpoint) -> (destination_trust, resource kind, resource asset kind, returns_content).
PINNED_SEMANTICS: Final[dict[tuple[str, str | None], tuple[str, str, str | None, bool]]] = {
    # A2: file_search returns canonical paths only - never content, never a taint source.
    ("file_search", None): ("internal", "none", None, False),
    ("file_read", None): ("internal", "argument", "file", True),
    ("database_query", None): ("internal", "argument", "table", True),
    # A3: directory_lookup reads a public api_data asset.
    ("mock_api", "directory_lookup"): ("internal", "fixed_asset", "api_data", True),
    # The scenario exfiltration sink (FR-002).
    ("mock_api", "send_message"): ("external", "none", None, False),
}


class ToolDefinitions(ArtifactModel):
    ARTIFACT_KIND: ClassVar[str] = "tool_definitions"

    version: ToolDefinitionsVersion
    tools: ToolSet

    def identity(self) -> tuple[str, str]:
        return ("tool_definitions", self.version)

    def entries(self) -> dict[tuple[str, str | None], ToolSpec]:
        """Every (tool, endpoint) pair; endpoint is None except for mock_api."""
        tools = self.tools
        return {
            ("file_search", None): tools.file_search,
            ("file_read", None): tools.file_read,
            ("database_query", None): tools.database_query,
            ("mock_api", "directory_lookup"): tools.mock_api.endpoints.directory_lookup,
            ("mock_api", "send_message"): tools.mock_api.endpoints.send_message,
        }

    @model_validator(mode="after")
    def _pinned(self) -> ToolDefinitions:
        entries = self.entries()
        for key, spec in entries.items():
            name = key[0] if key[1] is None else f"{key[0]}.{key[1]}"
            declared = frozenset(spec.arguments)
            if declared != PINNED_ARGUMENTS[key]:
                extra = sorted(declared - PINNED_ARGUMENTS[key])
                missing = sorted(PINNED_ARGUMENTS[key] - declared)
                raise fail(
                    IssueType.UNDECLARED_ARGUMENT,
                    f"{name}: arguments must be exactly {sorted(PINNED_ARGUMENTS[key])} "
                    f"(extra {extra}, missing {missing})",
                    name,
                )
            trust, resource_kind, asset_kind, returns = PINNED_SEMANTICS[key]
            actual_asset_kind = getattr(spec.resource, "asset_kind", None)
            if (
                spec.destination_trust,
                spec.resource.kind,
                actual_asset_kind,
                spec.returns_content,
            ) != (
                trust,
                resource_kind,
                asset_kind,
                returns,
            ):
                raise fail(
                    IssueType.INCONSISTENT,
                    f"{name}: destination_trust/resource/returns_content must be "
                    f"{trust}/{resource_kind}:{asset_kind}/{returns} (ARCHITECTURE.md §16)",
                    name,
                )
        require_unique(entries, lambda k: k, "tool entry")
        return self
