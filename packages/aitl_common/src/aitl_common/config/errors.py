"""Machine-readable configuration validation errors.

Every rejection names the artifact, its version (when it could be read), the
field path inside it, a closed error type, and the identifier involved, so a
failed load can be reported and tested precisely. Validation never
auto-corrects, skips, or substitutes a default: any issue fails the load.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

__all__ = ["ArtifactIssue", "ConfigValidationError", "IssueType"]


class IssueType(StrEnum):
    # Reading and parsing
    FILE_ACCESS = "file_access"
    FILE_TOO_LARGE = "file_too_large"
    UNEXPECTED_FILE = "unexpected_file"
    MISSING_ARTIFACT = "missing_artifact"
    ENCODING = "encoding"
    YAML_SYNTAX = "yaml_syntax"
    YAML_DUPLICATE_KEY = "yaml_duplicate_key"
    YAML_FORBIDDEN_CONSTRUCT = "yaml_forbidden_construct"
    # Schema
    MISSING_FIELD = "missing_field"
    UNKNOWN_FIELD = "unknown_field"
    INVALID_TYPE = "invalid_type"
    INVALID_ENUM = "invalid_enum"
    INVALID_FORMAT = "invalid_format"
    INVALID_VALUE = "invalid_value"
    # Identity and versioning
    VERSION_MISMATCH = "version_mismatch"
    DUPLICATE_ID = "duplicate_id"
    DUPLICATE_VERSION = "duplicate_version"
    DUPLICATE_RULE = "duplicate_rule"
    # Semantics and cross-references
    UNKNOWN_REFERENCE = "unknown_reference"
    UNSUPPORTED_TOOL = "unsupported_tool"
    UNSUPPORTED_TECHNIQUE = "unsupported_technique"
    UNSUPPORTED_LABEL = "unsupported_label"
    UNDECLARED_PARAMETER = "undeclared_parameter"
    UNDECLARED_ARGUMENT = "undeclared_argument"
    RULE_OVERLAP = "rule_overlap"
    DEAD_RULE = "dead_rule"
    INCONSISTENT = "inconsistent"
    FORBIDDEN_CONTENT = "forbidden_content"
    # Registration (database)
    HASH_MISMATCH = "hash_mismatch"


@dataclass(frozen=True, slots=True)
class ArtifactIssue:
    artifact: str
    version: str | None
    path: str
    error_type: IssueType
    identifier: str | None
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact": self.artifact,
            "version": self.version,
            "path": self.path,
            "error_type": self.error_type.value,
            "identifier": self.identifier,
            "message": self.message,
        }


class ConfigValidationError(Exception):
    """One or more issues; the configuration must not be used."""

    def __init__(self, issues: Iterable[ArtifactIssue]) -> None:
        self.issues: tuple[ArtifactIssue, ...] = tuple(issues)
        if not self.issues:
            raise ValueError("ConfigValidationError requires at least one issue")
        first = self.issues[0]
        more = f" (+{len(self.issues) - 1} more)" if len(self.issues) > 1 else ""
        super().__init__(
            f"{first.artifact}@{first.version}: {first.path}: {first.error_type.value}: "
            f"{first.message}{more}"
        )

    def to_dicts(self) -> list[dict[str, Any]]:
        return [issue.to_dict() for issue in self.issues]

    def types(self) -> set[IssueType]:
        return {issue.error_type for issue in self.issues}


def issue(
    artifact: str,
    version: str | None,
    path: str,
    error_type: IssueType,
    message: str,
    identifier: str | None = None,
) -> ArtifactIssue:
    return ArtifactIssue(artifact, version, path, error_type, identifier, message)


# Pydantic error types -> IssueType. Custom validators raise PydanticCustomError
# whose type is an IssueType value, which is passed through unchanged.
_PYDANTIC_TYPES: Mapping[str, IssueType] = {
    "missing": IssueType.MISSING_FIELD,
    "extra_forbidden": IssueType.UNKNOWN_FIELD,
    "literal_error": IssueType.INVALID_ENUM,
    "enum": IssueType.INVALID_ENUM,
    "string_pattern_mismatch": IssueType.INVALID_FORMAT,
    "union_tag_invalid": IssueType.INVALID_ENUM,
    "union_tag_not_found": IssueType.MISSING_FIELD,
}


def pydantic_issue_type(error_type: str) -> IssueType:
    if error_type in _PYDANTIC_TYPES:
        return _PYDANTIC_TYPES[error_type]
    try:
        return IssueType(error_type)
    except ValueError:
        pass
    if error_type.endswith("_type") or error_type.endswith("_parsing"):
        return IssueType.INVALID_TYPE
    return IssueType.INVALID_VALUE
