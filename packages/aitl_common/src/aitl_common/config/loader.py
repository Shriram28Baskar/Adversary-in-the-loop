"""Confined, fail-closed reading and validation of one artifact file.

Pipeline for every YAML artifact::

    bytes (confined, size-limited) -> strict UTF-8 -> strict YAML subset
      -> canonical JSON (P0 ``canonical_json``) -> strict schema (JSON mode)
      -> semantic validators -> immutable model + content hash

The content hash is ``canonical_sha256(model.model_dump(mode="json"))``: the
hash of the *validated* content, so comments, key order, quoting and
whitespace do not change it, while any semantic change does. Raw files
(prompts, fixture documents) are hashed byte-for-byte with ``sha256_hex``.

Files are read only from inside one configuration root: absolute paths, ``..``
components, symlinks anywhere on the path and non-regular files are refused.
There is no API that parses configuration from a string or a database row, so
attacker-derived data can never be turned into configuration by serializing it.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Final, Generic, TypeVar

from pydantic import BaseModel, TypeAdapter, ValidationError

from aitl_common.canonical_json import CanonicalJSONError, canonical_sha256, dumps, sha256_hex
from aitl_common.config import strict_yaml
from aitl_common.config.errors import (
    ArtifactIssue,
    ConfigValidationError,
    IssueType,
    issue,
    pydantic_issue_type,
)

__all__ = [
    "MAX_TEXT_BYTES",
    "MAX_YAML_BYTES",
    "ConfigRoot",
    "LoadedArtifact",
    "RawFile",
    "content_sha256",
]

MAX_YAML_BYTES: Final = 256 * 1024
MAX_TEXT_BYTES: Final = 64 * 1024

M = TypeVar("M", bound=BaseModel)


def content_sha256(model: BaseModel) -> str:
    """Hash of the validated, canonical content of an artifact."""
    return canonical_sha256(model.model_dump(mode="json"))


@dataclass(frozen=True, slots=True)
class LoadedArtifact(Generic[M]):
    source: str  # path relative to the configuration root
    model: M
    content_sha256: str


@dataclass(frozen=True, slots=True)
class RawFile:
    source: str
    data: bytes
    sha256: str

    @property
    def text(self) -> str:
        return self.data.decode("utf-8")


def _version_hint(data: Any) -> str | None:
    if isinstance(data, Mapping):
        value = data.get("version")
        if isinstance(value, str | int) and not isinstance(value, bool):
            return str(value)
    return None


def _loc(loc: tuple[int | str, ...]) -> str:
    path = ""
    for part in loc:
        path += f"[{part}]" if isinstance(part, int) else (f".{part}" if path else str(part))
    return path or "$"


def _validation_issues(
    source: str, version: str | None, error: ValidationError
) -> list[ArtifactIssue]:
    issues = []
    for detail in error.errors(include_url=False):
        context = detail.get("ctx") or {}
        identifier = context.get("identifier")
        if identifier is None and detail["type"] in ("extra_forbidden", "missing"):
            identifier = str(detail["loc"][-1]) if detail["loc"] else None
        issues.append(
            issue(
                source,
                version,
                _loc(tuple(detail["loc"])),
                pydantic_issue_type(detail["type"]),
                str(detail["msg"]),
                None if identifier is None else str(identifier),
            )
        )
    return issues


class ConfigRoot:
    """Read-only, confined view of one configuration directory."""

    def __init__(self, root: Path) -> None:
        if root.is_symlink():
            raise ConfigValidationError(
                [issue(str(root), None, "$", IssueType.FILE_ACCESS, "root is a symlink")]
            )
        resolved = root.resolve(strict=False)
        if not resolved.is_dir():
            raise ConfigValidationError(
                [issue(str(root), None, "$", IssueType.MISSING_ARTIFACT, "not a directory")]
            )
        self.path = resolved

    def _checked(self, relative: str, *, directory: bool) -> Path:
        pure = PurePosixPath(relative)
        if pure.is_absolute() or not pure.parts or any(p in ("", ".", "..") for p in pure.parts):
            raise ConfigValidationError(
                [issue(relative, None, "$", IssueType.FILE_ACCESS, "path escapes the config root")]
            )
        current = self.path
        for part in pure.parts:
            current = current / part
            try:
                mode = os.lstat(current).st_mode
            except FileNotFoundError:
                raise ConfigValidationError(
                    [issue(relative, None, "$", IssueType.MISSING_ARTIFACT, "file does not exist")]
                ) from None
            if stat.S_ISLNK(mode):
                raise ConfigValidationError(
                    [issue(relative, None, "$", IssueType.FILE_ACCESS, "symlinks are not allowed")]
                )
        wanted = stat.S_ISDIR if directory else stat.S_ISREG
        if not wanted(os.lstat(current).st_mode):
            kind = "a directory" if directory else "a regular file"
            raise ConfigValidationError(
                [issue(relative, None, "$", IssueType.FILE_ACCESS, f"not {kind}")]
            )
        return current

    def exists(self, relative: str) -> bool:
        return os.path.lexists(self.path / relative)

    def list_dir(self, relative: str = "") -> list[str]:
        """Sorted entry names; directories get a trailing '/'. Symlinks are refused."""
        directory = self._checked(relative, directory=True) if relative else self.path
        names = []
        for entry in sorted(os.scandir(directory), key=lambda e: e.name):
            if entry.is_symlink():
                where = f"{relative}/{entry.name}" if relative else entry.name
                raise ConfigValidationError(
                    [issue(where, None, "$", IssueType.FILE_ACCESS, "symlinks are not allowed")]
                )
            names.append(entry.name + "/" if entry.is_dir() else entry.name)
        return names

    def read(self, relative: str, limit: int) -> RawFile:
        path = self._checked(relative, directory=False)
        size = os.lstat(path).st_size
        if size > limit:
            raise ConfigValidationError(
                [issue(relative, None, "$", IssueType.FILE_TOO_LARGE, f"{size} > {limit} bytes")]
            )
        data = path.read_bytes()
        if data.startswith(b"\xef\xbb\xbf"):
            raise ConfigValidationError(
                [issue(relative, None, "$", IssueType.ENCODING, "UTF-8 BOM is not allowed")]
            )
        try:
            data.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ConfigValidationError(
                [issue(relative, None, "$", IssueType.ENCODING, f"invalid UTF-8: {exc.reason}")]
            ) from None
        return RawFile(relative, data, sha256_hex(data))

    def load_text(self, relative: str) -> RawFile:
        raw = self.read(relative, MAX_TEXT_BYTES)
        bad = [c for c in raw.text if (ord(c) < 32 and c not in "\n\t") or ord(c) == 127]
        if bad:
            raise ConfigValidationError(
                [
                    issue(
                        relative,
                        None,
                        "$",
                        IssueType.FORBIDDEN_CONTENT,
                        "control characters are not allowed",
                        repr(bad[0]),
                    )
                ]
            )
        return raw

    def load_yaml(self, relative: str, schema: Any) -> LoadedArtifact[Any]:
        """Load and validate one YAML artifact against a model class or annotated union."""
        raw = self.read(relative, MAX_YAML_BYTES)
        try:
            data = strict_yaml.load(raw.text)
        except strict_yaml.StrictYAMLError as exc:
            error_type = {
                "duplicate_key": IssueType.YAML_DUPLICATE_KEY,
                "forbidden_construct": IssueType.YAML_FORBIDDEN_CONSTRUCT,
            }.get(exc.kind, IssueType.YAML_SYNTAX)
            where = "$" if exc.line is None else f"line {exc.line}"
            raise ConfigValidationError(
                [issue(relative, None, where, error_type, str(exc))]
            ) from None
        version = _version_hint(data)
        try:
            canonical = dumps(data)
        except CanonicalJSONError as exc:
            raise ConfigValidationError(
                [issue(relative, version, "$", IssueType.INVALID_VALUE, str(exc))]
            ) from None
        adapter = schema if isinstance(schema, TypeAdapter) else TypeAdapter(schema)
        try:
            model = adapter.validate_json(canonical, strict=True)
        except ValidationError as exc:
            raise ConfigValidationError(_validation_issues(relative, version, exc)) from None
        return LoadedArtifact(relative, model, content_sha256(model))
