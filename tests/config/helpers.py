"""Mutation helpers for configuration tests.

Every negative test copies the real ``config/`` tree, changes exactly one
thing, and asserts the precise machine-readable issue the loader reports - so
each rule is shown to fire against otherwise-valid v1 configuration.
"""

from __future__ import annotations

import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

from aitl_common.config import strict_yaml
from aitl_common.config.bundle import ConfigBundle, load_config
from aitl_common.config.errors import ArtifactIssue, ConfigValidationError, IssueType

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_ROOT = REPO_ROOT / "config"


def copy_config(tmp_path: Path) -> Path:
    target = tmp_path / "config"
    shutil.copytree(CONFIG_ROOT, target, symlinks=True)
    return target


def read_yaml(root: Path, relative: str) -> Any:
    return strict_yaml.load((root / relative).read_text(encoding="utf-8"))


class _NoAliasDumper(yaml.SafeDumper):
    # Mutations may share nested objects; emit them in full, never as anchors
    # (which the strict loader rightly rejects).
    def ignore_aliases(self, data: Any) -> bool:
        return True


def write_yaml(root: Path, relative: str, data: Any) -> None:
    (root / relative).write_text(
        yaml.dump(data, Dumper=_NoAliasDumper, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )


def mutate(root: Path, relative: str, change: Callable[[Any], object]) -> None:
    """Apply an in-place change to a YAML artifact (the return value is ignored)."""
    data = read_yaml(root, relative)
    change(data)
    write_yaml(root, relative, data)


def load_issues(root: Path) -> list[ArtifactIssue]:
    with pytest.raises(ConfigValidationError) as caught:
        load_config(root)
    return list(caught.value.issues)


def assert_issue(
    root: Path,
    error_type: IssueType,
    *,
    artifact: str | None = None,
    identifier: str | None = None,
) -> ArtifactIssue:
    issues = load_issues(root)
    for found in issues:
        if found.error_type != error_type:
            continue
        if artifact is not None and artifact not in found.artifact:
            continue
        if identifier is not None and found.identifier != identifier:
            continue
        return found
    raise AssertionError(
        f"expected {error_type.value} (artifact={artifact}, identifier={identifier}); got "
        + "; ".join(f"{i.artifact}:{i.path}:{i.error_type.value}:{i.identifier}" for i in issues)
    )


def load_valid(root: Path = CONFIG_ROOT) -> ConfigBundle:
    return load_config(root)
