"""Confined file access and canonical hashing of configuration artifacts (P2)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from aitl_common.canonical_json import canonical_sha256, sha256_hex
from aitl_common.config.errors import ConfigValidationError, IssueType
from aitl_common.config.loader import MAX_YAML_BYTES, ConfigRoot, content_sha256
from aitl_common.config.schemas.evaluation import EvalConfig
from tests.config.helpers import CONFIG_ROOT, copy_config

# --- confined access ---------------------------------------------------------------


@pytest.mark.parametrize("path", ["../pyproject.toml", "/etc/passwd", "eval/../../x", "./eval"])
def test_reads_outside_the_root_are_refused(path: str) -> None:
    with pytest.raises(ConfigValidationError) as caught:
        ConfigRoot(CONFIG_ROOT).read(path, 1024)
    assert caught.value.types() == {IssueType.FILE_ACCESS}


def test_symlinked_file_is_refused(tmp_path: Path) -> None:
    root = copy_config(tmp_path)
    target = root / "eval" / "eval-v1.yaml"
    moved = tmp_path / "outside.yaml"
    target.rename(moved)
    os.symlink(moved, target)
    with pytest.raises(ConfigValidationError) as caught:
        ConfigRoot(root).load_yaml("eval/eval-v1.yaml", EvalConfig)
    assert caught.value.types() == {IssueType.FILE_ACCESS}


def test_symlinked_directory_is_refused(tmp_path: Path) -> None:
    root = copy_config(tmp_path)
    (root / "eval").rename(tmp_path / "real-eval")
    os.symlink(tmp_path / "real-eval", root / "eval")
    with pytest.raises(ConfigValidationError) as caught:
        ConfigRoot(root).load_yaml("eval/eval-v1.yaml", EvalConfig)
    assert caught.value.types() == {IssueType.FILE_ACCESS}


def test_symlinked_root_is_refused(tmp_path: Path) -> None:
    os.symlink(CONFIG_ROOT, tmp_path / "link")
    with pytest.raises(ConfigValidationError):
        ConfigRoot(tmp_path / "link")


def test_oversized_file_is_refused(tmp_path: Path) -> None:
    (tmp_path / "big.yaml").write_bytes(b"a: " + b"x" * MAX_YAML_BYTES + b"\n")
    with pytest.raises(ConfigValidationError) as caught:
        ConfigRoot(tmp_path).load_yaml("big.yaml", EvalConfig)
    assert caught.value.types() == {IssueType.FILE_TOO_LARGE}


@pytest.mark.parametrize("data", [b"\xef\xbb\xbfversion: eval-v1\n", b"version: \xff\xfe\n"])
def test_bad_encoding_is_refused(tmp_path: Path, data: bytes) -> None:
    (tmp_path / "x.yaml").write_bytes(data)
    with pytest.raises(ConfigValidationError) as caught:
        ConfigRoot(tmp_path).load_yaml("x.yaml", EvalConfig)
    assert caught.value.types() == {IssueType.ENCODING}


def test_control_characters_in_text_artifacts_are_refused(tmp_path: Path) -> None:
    (tmp_path / "p.md").write_text("hello\x1b[31m world\n")
    with pytest.raises(ConfigValidationError) as caught:
        ConfigRoot(tmp_path).load_text("p.md")
    assert caught.value.types() == {IssueType.FORBIDDEN_CONTENT}


def test_errors_are_machine_readable(tmp_path: Path) -> None:
    (tmp_path / "e.yaml").write_text("version: eval-v1\nweights: {}\nthresholds: []\nextra: 1\n")
    with pytest.raises(ConfigValidationError) as caught:
        ConfigRoot(tmp_path).load_yaml("e.yaml", EvalConfig)
    dicts = caught.value.to_dicts()
    assert {d["error_type"] for d in dicts} >= {"missing_field", "unknown_field"}
    for d in dicts:
        assert set(d) == {"artifact", "version", "path", "error_type", "identifier", "message"}
        assert d["artifact"] == "e.yaml"
        assert d["version"] == "eval-v1"
    assert any(d["identifier"] == "extra" and d["path"] == "extra" for d in dicts)


# --- canonical hashing -------------------------------------------------------------


def test_hash_is_stable_across_loads() -> None:
    first = ConfigRoot(CONFIG_ROOT).load_yaml("eval/eval-v1.yaml", EvalConfig)
    second = ConfigRoot(CONFIG_ROOT).load_yaml("eval/eval-v1.yaml", EvalConfig)
    assert first.content_sha256 == second.content_sha256
    assert first.content_sha256 == canonical_sha256(first.model.model_dump(mode="json"))


def test_equivalent_representations_hash_identically(tmp_path: Path) -> None:
    """Comments, key order, flow vs block style and quoting do not change the hash."""
    block = """
# a comment
version: eval-v1
thresholds:
  - {label: MINIMAL, min: 0, max: 0}
  - {max: 5, label: LOW, min: 1}
  - label: MODERATE
    min: 6
    max: 20
  - {label: HIGH, min: 21, max: null}
weights:
  X_succeeded: 10
  R_public: 1
  R_private: 3
  "R_sensitive": 7
  U_allowed: 2
"""
    (tmp_path / "a.yaml").write_text(block)
    reordered = ConfigRoot(tmp_path).load_yaml("a.yaml", EvalConfig)
    original = ConfigRoot(CONFIG_ROOT).load_yaml("eval/eval-v1.yaml", EvalConfig)
    assert reordered.content_sha256 == original.content_sha256


def test_semantic_change_changes_the_hash(tmp_path: Path) -> None:
    text = (CONFIG_ROOT / "eval" / "eval-v1.yaml").read_text().replace("R_public: 1", "R_public: 2")
    (tmp_path / "e.yaml").write_text(text)
    changed = ConfigRoot(tmp_path).load_yaml("e.yaml", EvalConfig)
    original = ConfigRoot(CONFIG_ROOT).load_yaml("eval/eval-v1.yaml", EvalConfig)
    assert changed.content_sha256 != original.content_sha256


def test_decimal_spelling_does_not_change_the_hash(tmp_path: Path) -> None:
    root = copy_config(tmp_path)
    rules = root / "intel" / "ttp_rules_v1.yaml"
    rules.write_text(rules.read_text().replace("confidence: 0.40", "confidence: 0.4"))
    from aitl_common.config.schemas.intel import TtpRules

    a = ConfigRoot(root).load_yaml("intel/ttp_rules_v1.yaml", TtpRules)
    b = ConfigRoot(CONFIG_ROOT).load_yaml("intel/ttp_rules_v1.yaml", TtpRules)
    assert a.content_sha256 == b.content_sha256


def test_raw_files_hash_bytes_exactly() -> None:
    raw = ConfigRoot(CONFIG_ROOT).load_text("agents/prompts/system_v1.md")
    assert raw.sha256 == sha256_hex((CONFIG_ROOT / "agents/prompts/system_v1.md").read_bytes())


def test_content_hash_uses_p0_canonical_json() -> None:
    loaded = ConfigRoot(CONFIG_ROOT).load_yaml("eval/eval-v1.yaml", EvalConfig)
    assert content_sha256(loaded.model) == loaded.content_sha256
