"""Fixture set (PRD FR-003, FR-016, FR-024; ARCHITECTURE.md §14, §18, §37.4).

``config/fixtures/fixture_set_vN/manifest.yaml`` lists every asset with its
kind, locator, sensitivity tier and source file. All content is fabricated.

- ``asset_id`` is derived, not chosen: ``file:<path>``, ``table:<name>`` or
  ``api:<name>``, so an asset cannot be aliased under a second identity.
- A file's locator is a canonical absolute path whose first segment is its
  tier (``/sensitive/...``), and its source is ``files/<locator>``; table and
  API sources are ``db/<name>.yaml`` and ``api/<name>.yaml``. No other source
  path is expressible.
- Every ``private``/``sensitive`` asset carries markers (FR-024): exactly one
  ``CANARY_PLACEHOLDER``, replaced per execution by the Gateway with a canary
  derived from (fixture-set version, seed, asset ID), and at least one line
  long enough to fingerprint. Public assets carry none.
- ``fabricated_credentials`` lists every fake credential an asset contains;
  each must start with ``aitlfx-`` and appear in the asset, so tests can prove
  no fixture credential leaks elsewhere (FR-004c, SEC-003).
"""

from __future__ import annotations

from typing import Annotated, ClassVar, Final, Literal

from pydantic import Field, StringConstraints, TypeAdapter, ValidationError, model_validator

from aitl_common.config.errors import IssueType
from aitl_common.config.schemas.base import ArtifactModel, ConfigModel, fail, require_unique
from aitl_common.config.vocabulary import (
    AssetId,
    AssetKind,
    ColumnName,
    ColumnType,
    FixturePath,
    FixtureSetVersion,
    TableName,
    Tier,
    asset_id_for,
)

# Replaced per execution by the Gateway (P9); never a real value.
CANARY_PLACEHOLDER: Final = "AITL-CANARY-PLACEHOLDER"
# ARCHITECTURE.md §18: content fingerprints hash normalized lines of >= 24 characters.
FINGERPRINT_MIN_LINE: Final = 24
FABRICATED_PREFIX: Final = "aitlfx-"
MAX_FIXTURE_FILE_BYTES: Final = 64 * 1024

FabricatedCredential = Annotated[str, StringConstraints(pattern=r"^aitlfx-[A-Za-z0-9-]{8,64}$")]
SourcePath = Annotated[
    str,
    StringConstraints(
        pattern=r"^(?:files(?:/[a-z0-9_-][a-z0-9_.-]{0,63}){1,8}|(?:db|api)/[a-z][a-z0-9_]{0,62}\.yaml)$"
    ),
]

_PATH_ADAPTER: Final = TypeAdapter(FixturePath)
_NAME_ADAPTER: Final = TypeAdapter(TableName)


def _check_path(value: str, identifier: str) -> None:
    try:
        _PATH_ADAPTER.validate_python(value, strict=True)
    except ValidationError:
        raise fail(
            IssueType.INVALID_FORMAT, f"{value!r} is not a canonical fixture path", identifier
        ) from None


def _check_name(value: str, identifier: str) -> None:
    try:
        _NAME_ADAPTER.validate_python(value, strict=True)
    except ValidationError:
        raise fail(
            IssueType.INVALID_FORMAT, f"{value!r} is not a valid table/dataset name", identifier
        ) from None


class FixtureAsset(ConfigModel):
    asset_id: AssetId
    kind: AssetKind
    locator: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    tier: Tier
    has_markers: bool
    source: SourcePath
    fabricated_credentials: tuple[FabricatedCredential, ...] = Field(max_length=16)

    @model_validator(mode="after")
    def _check(self) -> FixtureAsset:
        if self.kind == "file":
            _check_path(self.locator, self.asset_id)
            if self.locator.split("/")[1] != self.tier:
                raise fail(
                    IssueType.INCONSISTENT,
                    f"{self.asset_id}: file under /{self.locator.split('/')[1]}/ must have "
                    f"that tier, not {self.tier}",
                    self.asset_id,
                )
            expected_source = f"files{self.locator}"
        else:
            _check_name(self.locator, self.asset_id)
            expected_source = f"{'db' if self.kind == 'table' else 'api'}/{self.locator}.yaml"
        if self.asset_id != asset_id_for(self.kind, self.locator):
            raise fail(
                IssueType.INCONSISTENT,
                f"asset_id must be {asset_id_for(self.kind, self.locator)!r}",
                self.asset_id,
            )
        if self.source != expected_source:
            raise fail(
                IssueType.INCONSISTENT,
                f"{self.asset_id}: source must be {expected_source!r}",
                self.asset_id,
            )
        if self.has_markers != (self.tier != "public"):
            raise fail(
                IssueType.INCONSISTENT,
                f"{self.asset_id}: has_markers must be true exactly for private/sensitive (FR-024)",
                self.asset_id,
            )
        if self.fabricated_credentials and self.tier == "public":
            raise fail(
                IssueType.INCONSISTENT,
                f"{self.asset_id}: public assets must not contain credentials",
                self.asset_id,
            )
        require_unique(self.fabricated_credentials, lambda c: c, "fabricated credential")
        return self


class FixtureSetManifest(ArtifactModel):
    ARTIFACT_KIND: ClassVar[str] = "fixture_set"

    version: FixtureSetVersion
    assets: tuple[FixtureAsset, ...] = Field(min_length=1, max_length=64)

    def identity(self) -> tuple[str, str]:
        return ("fixture_set", self.version)

    @model_validator(mode="after")
    def _check(self) -> FixtureSetManifest:
        require_unique(self.assets, lambda a: a.asset_id, "asset id")
        require_unique(self.assets, lambda a: (a.kind, a.locator), "(kind, locator)")
        credentials = [c for a in self.assets for c in a.fabricated_credentials]
        require_unique(credentials, lambda c: c, "fabricated credential across assets")
        return self

    def asset(self, asset_id: str) -> FixtureAsset | None:
        return next((a for a in self.assets if a.asset_id == asset_id), None)

    def file_asset_by_path(self, path: str) -> FixtureAsset | None:
        return next((a for a in self.assets if a.kind == "file" and a.locator == path), None)


class Column(ConfigModel):
    name: ColumnName
    type: ColumnType


CellValue = (
    Annotated[str, StringConstraints(max_length=512)]
    | Annotated[int, Field(ge=-(2**31), le=2**31 - 1)]
)


class TabularData(ConfigModel):
    """A mock database table (``db/*.yaml``) or mock API dataset (``api/*.yaml``)."""

    name: TableName
    kind: Literal["table", "api_data"]
    columns: tuple[Column, ...] = Field(min_length=1, max_length=16)
    rows: tuple[dict[ColumnName, CellValue], ...] = Field(min_length=1, max_length=200)

    @model_validator(mode="after")
    def _check(self) -> TabularData:
        require_unique(self.columns, lambda c: c.name, "column")
        names = [c.name for c in self.columns]
        types = {c.name: c.type for c in self.columns}
        for index, row in enumerate(self.rows):
            if set(row) != set(names):
                raise fail(
                    IssueType.INCONSISTENT,
                    f"row {index}: columns {sorted(row)} != declared {sorted(names)}",
                    f"{self.name}[{index}]",
                )
            for column, value in row.items():
                if (types[column] == "integer") != isinstance(value, int):
                    raise fail(
                        IssueType.INVALID_TYPE,
                        f"row {index}: {column} must be {types[column]}",
                        f"{self.name}[{index}].{column}",
                    )
        return self

    def text(self) -> str:
        """One line per row (columns in declared order): the unit markers and
        fingerprints are computed over for tabular assets."""
        names = [c.name for c in self.columns]
        return "\n".join(" | ".join(str(row[n]) for n in names) for row in self.rows)
