"""Single writer for TTP intelligence (P5-D12; ARCHITECTURE.md ADR-025).

Exactly one production module may write ``intel.ttp`` and
``intel.ttp_technique``: ``intel_service/classification.py`` (created by the
P5 implementation; it does not exist yet). No other module names ``TTP`` or
``TTPTechnique`` in an ``insert(...)``, and no SQL string inserts into those
tables. Until P5 is implemented, there is no writer at all.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PRODUCTION_ROOTS = [REPO_ROOT / "packages", REPO_ROOT / "services"]
DESIGNATED_WRITER = (
    REPO_ROOT / "services" / "intel_service" / "src" / "intel_service" / "classification.py"
)
MODELS = {"TTP", "TTPTechnique"}
TABLE_INSERT = re.compile(r"insert\s+into\s+intel\.(ttp|ttp_technique)\b", re.IGNORECASE)


def _production_files() -> list[Path]:
    files: list[Path] = []
    for root in PRODUCTION_ROOTS:
        files += [p for p in root.rglob("*.py") if "/src/" in str(p) and "/tests/" not in str(p)]
    return sorted(files)


def ttp_writes(tree: ast.AST) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
            if name == "insert" and node.args:
                target = node.args[0]
                target_name = (
                    target.id if isinstance(target, ast.Name) else getattr(target, "attr", "")
                )
                if target_name in MODELS:
                    found.add(target_name)
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            match = TABLE_INSERT.search(node.value)
            if match:
                found.add(match.group(1))
    return found


def test_only_the_designated_module_may_write_ttp_intelligence() -> None:
    writers = {
        p for p in _production_files() if ttp_writes(ast.parse(p.read_text(), filename=str(p)))
    }
    assert writers <= {DESIGNATED_WRITER}, sorted(str(w) for w in writers)


@pytest.mark.parametrize(
    "snippet",
    [
        "insert(TTP)",
        "sa.insert(models.TTPTechnique)",
        "text('INSERT INTO intel.ttp (label) VALUES (1)')",
        "q = 'insert into intel.ttp_technique values (1)'",
    ],
)
def test_writer_scan_detects_ttp_writes(snippet: str) -> None:
    assert ttp_writes(ast.parse(snippet))


def test_writer_scan_ignores_other_tables() -> None:
    assert not ttp_writes(ast.parse("insert(AttackSession); x = 'INSERT INTO intel.ttpx'"))
