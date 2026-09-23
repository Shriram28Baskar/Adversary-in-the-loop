"""P4 code boundaries (FR-005b; CLAUDE.md Forbidden Shortcuts; ADR-024).

- Only ``intel_service/promotion.py`` writes ``AttackSession``, ``AttackEvent``,
  ``AttackerBehavior`` and ``BehaviorEvent`` - no other production module
  names them in an insert, and no SQL string inserts into their tables.
- P4 modules execute nothing and reach nothing: no subprocess, socket, HTTP,
  dynamic import, eval/exec, pickle, or LLM client.
- P4 makes no later-phase judgement: it imports no TTP rule, ATT&CK mapping,
  abstraction, scenario, policy, or evaluation component.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
INTEL_SRC = REPO_ROOT / "services" / "intel_service" / "src" / "intel_service"
PRODUCTION_ROOTS = [REPO_ROOT / "packages", REPO_ROOT / "services"]
WRITER = INTEL_SRC / "promotion.py"
MODELS = {"AttackSession", "AttackEvent", "AttackerBehavior", "BehaviorEvent"}
TABLE_INSERT = re.compile(
    r"insert\s+into\s+intel\.(attack_session|attack_event|attacker_behavior|behavior_event)\b",
    re.IGNORECASE,
)
FORBIDDEN_MODULES = {
    "subprocess",
    "socket",
    "http",
    "urllib",
    "requests",
    "httpx",
    "importlib",
    "pickle",
    "marshal",
    "ctypes",
    "multiprocessing",
    "anthropic",
    "openai",
}
LATER_PHASE_NAMES = {
    "TtpRules",
    "TtpRule",
    "AttackMapping",
    "AbstractionTable",
    "TTP",
    "TTPTechnique",
    "AbstractedThreatPattern",
    "ThreatPatternSource",
    "Scenario",
    "ScenarioStep",
    "Policy",
    "EvalConfig",
}
LATER_PHASE_MODULES = {
    "security",
    "eval",
    "agent",
    "attack",
    "abstraction",
    "scenarios",
    "policies",
}
FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__"}


def _production_files() -> list[Path]:
    files: list[Path] = []
    for root in PRODUCTION_ROOTS:
        files += [p for p in root.rglob("*.py") if "/src/" in str(p) and "/tests/" not in str(p)]
    return sorted(files)


def insert_writers(tree: ast.AST) -> set[str]:
    """Model names used as the target of ``insert(...)``, plus raw SQL inserts."""
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


def test_writer_scan_covers_the_production_tree() -> None:
    files = _production_files()
    assert WRITER in files
    assert any(p.name == "service.py" and "log_shipper" in str(p) for p in files)


def test_only_promotion_writes_sessions_events_and_behaviors() -> None:
    writers = {
        str(p.relative_to(REPO_ROOT)): found
        for p in _production_files()
        if (found := insert_writers(ast.parse(p.read_text(), filename=str(p))))
    }
    assert writers == {str(WRITER.relative_to(REPO_ROOT)): MODELS}


@pytest.mark.parametrize(
    "snippet",
    [
        "insert(AttackSession)",
        "sa.insert(models.AttackEvent)",
        "insert(AttackerBehavior).values()",
        "x = 'INSERT INTO intel.behavior_event (a) VALUES (1)'",
        "text('insert  into intel.attack_session values (1)')",
    ],
)
def test_writer_scan_detects_other_writers(snippet: str) -> None:
    assert insert_writers(ast.parse(snippet))


def _imports_and_calls(path: Path) -> tuple[set[str], set[str], set[str]]:
    tree = ast.parse(path.read_text(), filename=str(path))
    modules: set[str] = set()
    names: set[str] = set()
    calls: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            modules.add(node.module or "")
            names |= {a.name for a in node.names}
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            calls.add(node.func.id)
    return modules, names, calls


@pytest.mark.parametrize("path", sorted(INTEL_SRC.rglob("*.py")), ids=lambda p: p.name)
def test_p4_executes_and_reaches_nothing(path: Path) -> None:
    modules, _, calls = _imports_and_calls(path)
    assert not {m.split(".")[0] for m in modules} & FORBIDDEN_MODULES
    assert not calls & FORBIDDEN_CALLS


@pytest.mark.parametrize("path", sorted(INTEL_SRC.rglob("*.py")), ids=lambda p: p.name)
def test_p4_makes_no_later_phase_judgement(path: Path) -> None:
    modules, names, _ = _imports_and_calls(path)
    assert not names & LATER_PHASE_NAMES, names & LATER_PHASE_NAMES
    for module in modules:
        parts = module.split(".")
        if parts[:2] in (["aitl_common", "db"], ["aitl_common", "config"]):
            assert not set(parts[2:]) & LATER_PHASE_MODULES, module
