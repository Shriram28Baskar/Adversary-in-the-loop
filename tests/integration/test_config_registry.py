"""Versioned configuration registration against real PostgreSQL (P2; plan §5.9; FR-022, FR-044).

The startup loaders insert each DB-loaded artifact as its owning runtime role,
are idempotent, never update a registered version, and refuse (without writing
anything) when a registered version's content hash differs - the in-place-edit
case that must stop a service from starting.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, text

from aitl_common.config.bundle import ConfigBundle, load_config
from aitl_common.config.errors import ConfigValidationError, IssueType
from aitl_common.config.registry import (
    RegistrationReport,
    agent_runtime_rows,
    register_agent_runtime_config,
    register_eval_configs,
    register_policies,
)
from aitl_common.db.engine import DatabaseSettings, create_role_engine
from tests.config.helpers import CONFIG_ROOT, copy_config
from tests.pg_harness import Cluster

REGISTERS: dict[str, tuple[str, Callable[[Engine, ConfigBundle], RegistrationReport]]] = {
    "agent_runtime": ("agent_svc", register_agent_runtime_config),
    "policies": ("gateway_svc", register_policies),
    "eval": ("eval_svc", register_eval_configs),
}
TABLES = (
    "agent.data_asset",
    "agent.tool",
    "agent.agent_task",
    "agent.agent_config",
    "security.policy",
    "eval.eval_config",
)


@pytest.fixture
def config_db(pg: Cluster, fresh_db: str) -> str:
    pg.upgrade(fresh_db)
    return fresh_db


@pytest.fixture
def engines(pg: Cluster, config_db: str) -> Iterator[dict[str, Engine]]:
    made = {
        role: create_role_engine(
            role,
            DatabaseSettings(
                host=pg.host, port=pg.port, dbname=config_db, user=role, password=pg.passwords[role]
            ),
        )
        for role in ("agent_svc", "gateway_svc", "eval_svc", "intel_svc")
    }
    yield made
    for engine in made.values():
        engine.dispose()


def _register_all(
    engines: dict[str, Engine], bundle: ConfigBundle
) -> dict[str, RegistrationReport]:
    return {name: fn(engines[role], bundle) for name, (role, fn) in REGISTERS.items()}


def _snapshot(pg: Cluster, db: str) -> dict[str, list[tuple[Any, ...]]]:
    with pg.admin(db) as conn:
        return {
            table: [
                tuple(r) for r in conn.execute(f"SELECT * FROM {table} ORDER BY 1, 2").fetchall()
            ]
            for table in TABLES
        }


def test_registration_inserts_every_config_row(
    pg: Cluster, config_db: str, engines: dict[str, Engine]
) -> None:
    bundle = load_config(CONFIG_ROOT)
    reports = _register_all(engines, bundle)
    assert all(not r.unchanged for r in reports.values())
    with pg.admin(config_db) as conn:
        counts = {t: conn.execute(f"SELECT count(*) FROM {t}").fetchone()[0] for t in TABLES}  # type: ignore[index]
        agents = conn.execute(
            "SELECT agent_id, agent_kind, provider, model_id, temperature, scripted_plans IS NULL, "
            "system_prompt_sha256, tool_schema_sha256 FROM agent.agent_config ORDER BY 1"
        ).fetchall()
        policy = conn.execute(
            "SELECT content_sha256, document->>'policy_id' FROM security.policy "
            "WHERE policy_id = 'target'"
        ).fetchone()
        tools = conn.execute(
            "SELECT tool_name, endpoint, destination_trust FROM agent.tool ORDER BY 1, 2"
        ).fetchall()
    assert counts == {
        "agent.data_asset": 8,
        "agent.tool": 5,
        "agent.agent_task": 1,
        "agent.agent_config": 2,
        "security.policy": 2,
        "eval.eval_config": 1,
    }
    prompt_sha = bundle.prompts[("system", 1)].sha256
    tools_sha = bundle.tool_definitions["tool-definitions-v1"].content_sha256
    assert [tuple(a) for a in agents] == [
        ("assistant_llm", "llm", "anthropic", "claude-sonnet-5", 0, True, prompt_sha, tools_sha),
        ("assistant_scripted", "scripted", None, None, 0, False, prompt_sha, tools_sha),
    ]
    assert policy == (bundle.policies[("target", 1)].content_sha256, "target")
    assert [tuple(t) for t in tools] == [
        ("file_search", "", "internal"),
        ("file_read", "", "internal"),
        ("database_query", "", "internal"),
        ("mock_api", "directory_lookup", "internal"),
        ("mock_api", "send_message", "external"),
    ]


def test_registration_is_idempotent(
    pg: Cluster, config_db: str, engines: dict[str, Engine]
) -> None:
    bundle = load_config(CONFIG_ROOT)
    _register_all(engines, bundle)
    before = _snapshot(pg, config_db)
    second = _register_all(engines, load_config(CONFIG_ROOT))
    assert all(not r.inserted and r.unchanged for r in second.values())
    assert _snapshot(pg, config_db) == before


def test_in_place_edit_is_refused_without_writing(
    pg: Cluster, config_db: str, engines: dict[str, Engine], tmp_path: Path
) -> None:
    _register_all(engines, load_config(CONFIG_ROOT))
    root = copy_config(tmp_path)
    policy = root / "policies" / "target_v1.yaml"
    policy.write_text(
        policy.read_text().replace(
            "description: Target policy - least privilege for the assistant role.",
            "description: Target policy - edited in place.",
        )
    )
    edited = load_config(root)  # still valid - but version 1 is already registered
    before = _snapshot(pg, config_db)
    with pytest.raises(ConfigValidationError) as caught:
        register_policies(engines["gateway_svc"], edited)
    assert caught.value.types() == {IssueType.HASH_MISMATCH}
    assert caught.value.issues[0].identifier == "security.policy[target, 1]"
    assert _snapshot(pg, config_db) == before


def test_conflict_rolls_back_the_whole_batch(
    pg: Cluster, config_db: str, engines: dict[str, Engine]
) -> None:
    """A later conflicting row must not leave earlier rows of the batch behind."""
    bundle = load_config(CONFIG_ROOT)
    keys = list(bundle.policies)
    assert keys.index(("baseline-permissive", 1)) < keys.index(("target", 1))
    with engines["gateway_svc"].begin() as conn:
        conn.execute(
            text(
                "INSERT INTO security.policy (policy_id, version, content_sha256, document) "
                "VALUES ('target', 1, repeat('0', 64), '{}'::jsonb)"
            )
        )
    with pytest.raises(ConfigValidationError) as caught:
        register_policies(engines["gateway_svc"], bundle)
    assert caught.value.types() == {IssueType.HASH_MISMATCH}
    with pg.admin(config_db) as conn:
        rows = conn.execute("SELECT policy_id FROM security.policy ORDER BY 1").fetchall()
    assert rows == [("target",)]  # baseline, inserted earlier in the batch, rolled back


@pytest.mark.parametrize(
    ("register", "wrong_role"),
    [
        (register_agent_runtime_config, "gateway_svc"),
        (register_policies, "agent_svc"),
        (register_eval_configs, "gateway_svc"),
        (register_policies, "intel_svc"),
    ],
)
def test_registry_refuses_the_wrong_role(
    engines: dict[str, Engine],
    register: Callable[[Engine, ConfigBundle], RegistrationReport],
    wrong_role: str,
) -> None:
    with pytest.raises(ConfigValidationError) as caught:
        register(engines[wrong_role], load_config(CONFIG_ROOT))
    assert caught.value.types() == {IssueType.INCONSISTENT}


def test_grants_block_cross_service_registration(engines: dict[str, Engine]) -> None:
    """Even bypassing the role check, the database denies another service's tables."""
    import sqlalchemy.exc

    with engines["agent_svc"].begin() as conn, pytest.raises(sqlalchemy.exc.ProgrammingError):
        conn.execute(
            text(
                "INSERT INTO security.policy (policy_id, version, content_sha256, document) "
                "VALUES ('x', 1, repeat('a', 64), '{}'::jsonb)"
            )
        )


def test_row_hashes_are_deterministic_and_cover_resolved_content() -> None:
    a = agent_runtime_rows(load_config(CONFIG_ROOT))
    b = agent_runtime_rows(load_config(CONFIG_ROOT))
    assert [r["content_sha256"] for _, r in a] == [r["content_sha256"] for _, r in b]
    bundle = load_config(CONFIG_ROOT)
    other_prompt = replace(bundle.prompts[("system", 1)], sha256="f" * 64)
    changed = replace(bundle, prompts={("system", 1): other_prompt})
    agent_hashes = {
        r["agent_id"]: r["content_sha256"] for t, r in agent_runtime_rows(bundle) if "agent_id" in r
    }
    changed_hashes = {
        r["agent_id"]: r["content_sha256"]
        for t, r in agent_runtime_rows(changed)
        if "agent_id" in r
    }
    assert all(agent_hashes[k] != changed_hashes[k] for k in agent_hashes)
