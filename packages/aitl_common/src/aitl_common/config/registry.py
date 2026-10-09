"""Register versioned configuration in the database (engineering plan §5.9; ARCHITECTURE.md §17).

The DB-loaded artifacts are ``agent.agent_config``, ``agent.agent_task``,
``agent.tool``, ``agent.data_asset`` (written by agent-runtime as
``agent_svc``), ``security.policy`` (gateway-service, ``gateway_svc``) and
``eval.eval_config`` (eval-service, ``eval_svc``). Rule, mapping, abstraction
and template tables stay files (§5.9).

Semantics - the startup loader of each service:

- a row that does not exist is inserted;
- a row that exists with the *same* ``content_sha256`` is left alone
  (idempotent: loading twice changes nothing);
- a row that exists with a *different* ``content_sha256`` is a
  ``hash_mismatch``: the version was edited in place. Nothing is written (one
  transaction) and the service must refuse to start. Versions are never
  updated; a change is a new version (FR-044).

The engine's session role is verified before writing, so a registry can never
run under an unexpected identity. Rows are built only from a validated
``ConfigBundle``; there is no way to register configuration from anything else.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import Connection, Engine, text

from aitl_common.canonical_json import canonical_sha256, dumps
from aitl_common.config.bundle import ConfigBundle
from aitl_common.config.errors import ConfigValidationError, IssueType, issue
from aitl_common.config.schemas.agents import LlmAgentConfig

__all__ = [
    "RegistrationReport",
    "agent_runtime_rows",
    "eval_config_rows",
    "policy_rows",
    "register_agent_runtime_config",
    "register_eval_configs",
    "register_policies",
]


@dataclass(frozen=True)
class _Table:
    name: str
    key: tuple[str, ...]
    jsonb: frozenset[str] = frozenset()


AGENT_CONFIG: Final = _Table(
    "agent.agent_config", ("agent_id", "version"), frozenset({"scripted_plans"})
)
AGENT_TASK: Final = _Table("agent.agent_task", ("task_id", "version"))
TOOL: Final = _Table(
    "agent.tool",
    ("tool_definitions_version", "tool_name", "endpoint"),
    frozenset({"argument_schema"}),
)
DATA_ASSET: Final = _Table("agent.data_asset", ("fixture_set_version", "asset_id"))
POLICY: Final = _Table("security.policy", ("policy_id", "version"), frozenset({"document"}))
EVAL_CONFIG: Final = _Table("eval.eval_config", ("version",), frozenset({"weights", "thresholds"}))


@dataclass(frozen=True)
class RegistrationReport:
    inserted: tuple[str, ...]
    unchanged: tuple[str, ...]


# --------------------------------------------------------------------------------------
# Row builders (pure; deterministic)
# --------------------------------------------------------------------------------------


def _row_hash(row: Mapping[str, Any]) -> str:
    return canonical_sha256({k: v for k, v in row.items() if k != "content_sha256"})


def agent_runtime_rows(bundle: ConfigBundle) -> list[tuple[_Table, dict[str, Any]]]:
    rows: list[tuple[_Table, dict[str, Any]]] = []
    for fixture_set in bundle.fixture_sets.values():
        for asset in fixture_set.manifest.model.assets:
            rows.append(
                (
                    DATA_ASSET,
                    {
                        "fixture_set_version": fixture_set.version,
                        "asset_id": asset.asset_id,
                        "kind": asset.kind,
                        "locator": asset.locator,
                        "tier": asset.tier,
                        "has_markers": asset.has_markers,
                        "content_sha256": fixture_set.asset_sha256(asset),
                    },
                )
            )
    for version, tools in bundle.tool_definitions.items():
        for (tool, endpoint), spec in tools.model.entries().items():
            row: dict[str, Any] = {
                "tool_definitions_version": version,
                "tool_name": tool,
                "endpoint": endpoint or "",
                "destination_trust": spec.destination_trust,
                "argument_schema": spec.model_dump(mode="json"),
            }
            row["content_sha256"] = _row_hash(row)
            rows.append((TOOL, row))
    for (task_id, task_version), task in bundle.tasks.items():
        rows.append(
            (
                AGENT_TASK,
                {
                    "task_id": task_id,
                    "version": task_version,
                    "prompt": task.model.prompt,
                    "task_document_path": task.model.document_path,
                    "task_fact_tokens": list(task.model.task_fact_tokens),
                    "content_sha256": task.content_sha256,
                },
            )
        )
    for (agent_id, agent_version), loaded in bundle.agents.items():
        agent = loaded.model
        prompt = bundle.prompts[(agent.system_prompt.prompt_id, agent.system_prompt.version)]
        tools_loaded = bundle.tool_definitions[agent.tool_definitions_version]
        plans: dict[str, Any] | None = None
        if not isinstance(agent, LlmAgentConfig):
            plans = {}
            for ref in agent.scripted_plans:
                plan = bundle.scripted_plans[(ref.template_id, ref.version)]
                plans[ref.template_id] = {
                    "version": ref.version,
                    "content_sha256": plan.content_sha256,
                    "plan": plan.model.model_dump(mode="json"),
                }
        agent_row: dict[str, Any] = {
            "agent_id": agent_id,
            "version": agent_version,
            "agent_kind": agent.agent_kind,
            "role": agent.role,
            "provider": agent.model.provider if isinstance(agent, LlmAgentConfig) else None,
            "model_id": agent.model.model_id if isinstance(agent, LlmAgentConfig) else None,
            "temperature": agent.generation.temperature,
            "max_tokens": agent.generation.max_tokens,
            "system_prompt": prompt.text,
            "system_prompt_sha256": prompt.sha256,
            "tool_definitions_version": agent.tool_definitions_version,
            # The tool schema the agent is given is the tool definitions artifact.
            "tool_schema_sha256": tools_loaded.content_sha256,
            "agent_loop_version": agent.agent_loop_version,
            "max_steps": agent.limits.max_steps,
            "model_call_budget": agent.limits.model_call_budget,
            "timeout_seconds": agent.limits.timeout_seconds,
            "scripted_plans": plans,
        }
        # Covers the resolved prompt, tool schema and plans, not just the YAML.
        agent_row["content_sha256"] = _row_hash(agent_row)
        rows.append((AGENT_CONFIG, agent_row))
    return rows


def policy_rows(bundle: ConfigBundle) -> list[tuple[_Table, dict[str, Any]]]:
    return [
        (
            POLICY,
            {
                "policy_id": policy_id,
                "version": version,
                "content_sha256": loaded.content_sha256,
                "document": loaded.model.model_dump(mode="json"),
            },
        )
        for (policy_id, version), loaded in bundle.policies.items()
    ]


def eval_config_rows(bundle: ConfigBundle) -> list[tuple[_Table, dict[str, Any]]]:
    return [
        (
            EVAL_CONFIG,
            {
                "version": version,
                "weights": loaded.model.weights.model_dump(mode="json"),
                "thresholds": [t.model_dump(mode="json") for t in loaded.model.thresholds],
                "content_sha256": loaded.content_sha256,
            },
        )
        for version, loaded in bundle.eval_configs.items()
    ]


# --------------------------------------------------------------------------------------
# Writers
# --------------------------------------------------------------------------------------


def _require_role(connection: Connection, role: str) -> None:
    current = connection.execute(text("SELECT current_user")).scalar_one()
    if current != role:
        raise ConfigValidationError(
            [
                issue(
                    "registry",
                    None,
                    "$",
                    IssueType.INCONSISTENT,
                    f"registry must run as {role}, not {current}",
                    str(current),
                )
            ]
        )


def _write(
    engine: Engine, role: str, rows: Sequence[tuple[_Table, dict[str, Any]]]
) -> RegistrationReport:
    inserted: list[str] = []
    unchanged: list[str] = []
    conflicts = []
    with engine.begin() as connection:
        _require_role(connection, role)
        for table, row in rows:
            columns = list(row)
            values = ", ".join(
                f"CAST(:{c} AS jsonb)" if c in table.jsonb else f":{c}" for c in columns
            )
            params = {
                c: (dumps(v).decode("utf-8") if c in table.jsonb and v is not None else v)
                for c, v in row.items()
            }
            key_sql = " AND ".join(f"{k} = :{k}" for k in table.key)
            label = f"{table.name}[{', '.join(str(row[k]) for k in table.key)}]"
            # Identifiers come only from this module's _Table constants and the row
            # builders' fixed keys; every value is a bound parameter.
            result = connection.execute(
                text(
                    f"INSERT INTO {table.name} ({', '.join(columns)}) VALUES ({values}) "  # noqa: S608
                    f"ON CONFLICT ({', '.join(table.key)}) DO NOTHING"
                ),
                params,
            )
            if result.rowcount == 1:
                inserted.append(label)
                continue
            stored = connection.execute(
                text(f"SELECT content_sha256 FROM {table.name} WHERE {key_sql}"),  # noqa: S608
                {k: row[k] for k in table.key},
            ).scalar_one()
            if stored == row["content_sha256"]:
                unchanged.append(label)
            else:
                conflicts.append(
                    issue(
                        table.name,
                        str(row[table.key[-1]]),
                        "content_sha256",
                        IssueType.HASH_MISMATCH,
                        f"stored hash {stored} != artifact hash {row['content_sha256']}: "
                        "a registered version was edited in place; create a new version",
                        label,
                    )
                )
        if conflicts:
            raise ConfigValidationError(conflicts)  # rolls the transaction back
    return RegistrationReport(tuple(inserted), tuple(unchanged))


def register_agent_runtime_config(engine: Engine, bundle: ConfigBundle) -> RegistrationReport:
    """agent-runtime startup: data assets, tools, tasks, agent configs (as agent_svc)."""
    return _write(engine, "agent_svc", agent_runtime_rows(bundle))


def register_policies(engine: Engine, bundle: ConfigBundle) -> RegistrationReport:
    """gateway-service startup: policies (as gateway_svc; FR-022, FR-023)."""
    return _write(engine, "gateway_svc", policy_rows(bundle))


def register_eval_configs(engine: Engine, bundle: ConfigBundle) -> RegistrationReport:
    """eval-service startup: EvalConfig versions (as eval_svc; FR-029a)."""
    return _write(engine, "eval_svc", eval_config_rows(bundle))
