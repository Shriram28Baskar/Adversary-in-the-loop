"""Third layer of append-only enforcement: no application code path mutates protected tables.

Layers 1 and 2 (grants, triggers) are enforced by PostgreSQL and tested in
test_db_grants.py / test_schema_constraints.py. This static check scans every
application source file (packages/ and services/, excluding tests) for:

- SQLAlchemy ``update()`` / ``delete()`` targeting an append-only model;
- raw SQL ``UPDATE``, ``DELETE FROM`` or ``TRUNCATE`` naming an append-only table;
- ``create_all`` / ``drop_all`` (DDL is owned by the migrations only).

The scanner itself is exercised against known-bad snippets so it cannot pass
vacuously.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any, cast

import pytest
from sqlalchemy import Table
from sqlalchemy.orm import Mapper

from aitl_common.db.models import Base

REPO_ROOT = Path(__file__).resolve().parents[2]
SCANNED_ROOTS = ("packages", "services")


def _table_name(mapper: Mapper[Any]) -> str:
    return cast(Table, mapper.local_table).fullname


APPEND_ONLY_MODELS = {
    mapper.class_.__name__
    for mapper in Base.registry.mappers
    if getattr(mapper.class_, "APPEND_ONLY", True)
}
APPEND_ONLY_TABLES = {
    _table_name(mapper)
    for mapper in Base.registry.mappers
    if getattr(mapper.class_, "APPEND_ONLY", True)
}
ALL_TABLES = {_table_name(mapper) for mapper in Base.registry.mappers}
_RAW_SQL = re.compile(
    r"\b(?:UPDATE|DELETE\s+FROM|TRUNCATE(?:\s+TABLE)?)\s+(?:ONLY\s+)?"
    r"([a-z_]+\.[a-z_]+)",
    re.IGNORECASE,
)


def scan_source(source: str) -> list[str]:
    findings: list[str] = []
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if name in {"update", "delete"} and node.args:
                target = node.args[0]
                target_name = (
                    target.id if isinstance(target, ast.Name) else getattr(target, "attr", "")
                )
                if target_name in APPEND_ONLY_MODELS:
                    findings.append(f"{name}({target_name})")
            if name in {"create_all", "drop_all"}:
                findings.append(name)
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            for match in _RAW_SQL.finditer(node.value):
                if match.group(1).lower() in APPEND_ONLY_TABLES:
                    findings.append(f"raw SQL mutates {match.group(1)}")
    return findings


def _application_files() -> list[Path]:
    files: list[Path] = []
    for root in SCANNED_ROOTS:
        base = REPO_ROOT / root
        if base.exists():
            files.extend(p for p in base.rglob("*.py") if "tests" not in p.parts)
    return files


def test_models_registry_is_complete() -> None:
    assert len(ALL_TABLES) == 33
    assert {"intel.scenario", "agent.execution"} == ALL_TABLES - APPEND_ONLY_TABLES


def test_application_code_never_mutates_append_only_tables() -> None:
    files = _application_files()
    assert files, "scanner found no application files"
    findings = [
        f"{path.relative_to(REPO_ROOT)}: {finding}"
        for path in files
        for finding in scan_source(path.read_text(encoding="utf-8"))
    ]
    assert findings == []


@pytest.mark.parametrize(
    "snippet",
    [
        "from sqlalchemy import update\nupdate(PolicyDecision).values(enforced_final='ALLOW')",
        "import sqlalchemy as sa\nsa.delete(ToolInvocation)",
        "delete(AttackEvent).where(True)",
        "conn.execute('UPDATE security.policy_decision SET enforced_final = 1')",
        "sql = 'DELETE FROM eval.replay_run WHERE true'",
        "q = 'truncate table security.trajectory'",
        "Base.metadata.create_all(engine)",
    ],
)
def test_scanner_detects_mutations(snippet: str) -> None:
    assert scan_source(snippet)


@pytest.mark.parametrize(
    "snippet",
    [
        "update(Execution).values(lifecycle='running')",
        "update(Scenario).values(status='reviewed')",
        "conn.execute('UPDATE agent.execution SET lifecycle = %s')",
        "conn.execute('INSERT INTO security.policy_decision VALUES (1)')",
        "select(PolicyDecision)",
    ],
)
def test_scanner_allows_permitted_operations(snippet: str) -> None:
    assert scan_source(snippet) == []
