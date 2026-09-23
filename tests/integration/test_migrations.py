"""Migration behavior (engineering plan P1; ARCHITECTURE.md §24).

Empty database -> head, strict ordering of 0001..0013, presence of every
schema, table, constraint, index, trigger and role, owner NOLOGIN, and a
downgrade/re-upgrade round trip on disposable databases.
"""

from __future__ import annotations

from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory

from tests.pg_harness import ALEMBIC_INI, OWNER_ROLE, RUNTIME_ROLES, Cluster

EXPECTED_REVISIONS = [f"{n:04d}" for n in range(1, 14)]
EXPECTED_FILES = [
    "0001_schemas_domain_enums.py",
    "0002_config_tables.py",
    "0003_intel_raw.py",
    "0004_intel_session_events.py",
    "0005_intel_behavior_ttp.py",
    "0006_intel_patterns.py",
    "0007_intel_scenario.py",
    "0008_agent_execution.py",
    "0009_security_telemetry.py",
    "0010_eval.py",
    "0011_ops_events.py",
    "0012_grants_and_immutability.py",
    "0013_scenario_writer_isolation.py",
]
SCHEMAS = {"intel_raw", "intel", "agent", "security", "eval", "ops"}
TABLES = {
    "intel_raw.raw_ingest_record",
    "intel_raw.quarantine_record",
    "intel.attack_session",
    "intel.attack_event",
    "intel.attacker_behavior",
    "intel.behavior_event",
    "intel.ttp",
    "intel.ttp_technique",
    "intel.abstracted_threat_pattern",
    "intel.threat_pattern_source",
    "intel.scenario",
    "intel.scenario_step",
    "agent.agent_config",
    "agent.agent_task",
    "agent.tool",
    "agent.data_asset",
    "agent.execution",
    "security.policy",
    "security.tool_invocation",
    "security.policy_decision",
    "security.tool_result",
    "security.data_flow_event",
    "security.security_violation",
    "security.system_failure_event",
    "security.model_call",
    "security.agent_final_response",
    "security.trajectory",
    "eval.eval_config",
    "eval.replay_pair",
    "eval.replay_run",
    "eval.blast_radius",
    "eval.evaluation_result",
    "ops.events",
}
EXPECTED_INDEXES = {
    "ix_quarantine_record_raw_record_id",
    "ix_attack_event_session_occurred_at",
    "ix_behavior_event_event_id",
    "ix_ttp_session_id",
    "ix_ttp_behavior_id",
    "ix_threat_pattern_source_ttp_id",
    "ix_scenario_threat_pattern_id",
    "ix_scenario_status",
    "ix_execution_lifecycle_queued_at",
    "ix_execution_scenario",
    "ix_data_flow_event_execution_kind",
    "ix_system_failure_event_execution_id",
}
# CHECK constraints (PK/UNIQUE/FK names are verified against the ORM in
# test_orm_ddl_consistency.py).
EXPECTED_CHECKS = {
    "ck_agent_config_version_positive",
    "ck_agent_config_scripted_plans",
    "ck_agent_config_llm_model",
    "ck_agent_config_limits",
    "ck_agent_task_version_positive",
    "ck_agent_task_fact_tokens",
    "ck_tool_endpoint",
    "ck_data_asset_markers",
    "ck_policy_version_positive",
    "ck_raw_ingest_record_source_ref",
    "ck_quarantine_record_reason_code",
    "ck_attack_session_cowrie_session_id",
    "ck_attack_session_src_port",
    "ck_attack_event_seq",
    "ck_attack_event_raw_text",
    "ck_attack_event_normalized_text",
    "ck_attack_event_username",
    "ck_attack_event_attempted_secret",
    "ck_attack_event_artifact_size",
    "ck_attacker_behavior_ordinal",
    "ck_attacker_behavior_interval",
    "ck_ttp_mapping",
    "ck_ttp_tactic_id",
    "ck_ttp_confidence",
    "ck_ttp_first_event_seq",
    "ck_ttp_technique_id",
    "ck_abstracted_threat_pattern_tool_categories",
    "ck_threat_pattern_source_ordinal",
    "ck_scenario_version_positive",
    "ck_scenario_step_ordinal",
    "ck_execution_enforces_target",
    "ck_execution_error_class",
    "ck_execution_termination_reason",
    "ck_tool_invocation_seq",
    "ck_tool_invocation_tool",
    "ck_tool_invocation_endpoint",
    "ck_tool_invocation_validation",
    "ck_policy_decision_seq",
    "ck_policy_decision_components",
    "ck_policy_decision_fail_closed",
    "ck_policy_decision_approval",
    "ck_policy_decision_latency",
    "ck_tool_result_seq",
    "ck_tool_result_not_dispatched",
    "ck_data_flow_event_seq",
    "ck_data_flow_event_tier",
    "ck_data_flow_event_sink",
    "ck_security_violation_seq",
    "ck_security_violation_target",
    "ck_security_violation_blocked",
    "ck_system_failure_event_seq",
    "ck_model_call_seq",
    "ck_model_call_ok",
    "ck_model_call_tokens",
    "ck_agent_final_response_seq",
    "ck_agent_final_response_text",
    "ck_agent_final_response_normalized_text",
    "ck_trajectory_step_count",
    "ck_replay_pair_repetitions",
    "ck_replay_run_role",
    "ck_replay_run_repetition",
    "ck_replay_run_order",
    "ck_replay_run_enforced_policy",
    "ck_blast_radius_non_negative",
    "ck_blast_radius_exfiltration",
    "ck_blast_radius_subsets",
    "ck_evaluation_result_counts",
    "ck_evaluation_result_drift",
    "ck_evaluation_result_single_observation",
    "ck_events_event_type",
}


def _script() -> ScriptDirectory:
    return ScriptDirectory.from_config(Config(str(ALEMBIC_INI)))


def _rows(pg: Cluster, db: str, sql: str) -> set[str]:
    with pg.admin(db) as conn:
        return {str(row[0]) for row in conn.execute(sql).fetchall()}


def test_revision_chain_is_linear_and_ordered() -> None:
    script = _script()
    assert script.get_heads() == ["0013"]
    chain = [rev.revision for rev in script.walk_revisions("base", "heads")]
    assert list(reversed(chain)) == EXPECTED_REVISIONS
    for revision in script.walk_revisions("base", "heads"):
        expected_down = None if revision.revision == "0001" else f"{int(revision.revision) - 1:04d}"
        assert revision.down_revision == expected_down
    files = sorted(p.name for p in (Path(ALEMBIC_INI).parent / "versions").glob("*.py"))
    assert files == EXPECTED_FILES


def test_upgrade_from_empty_step_by_step(pg: Cluster, fresh_db: str) -> None:
    assert _rows(pg, fresh_db, "SELECT nspname FROM pg_namespace") & SCHEMAS == set()
    for revision in EXPECTED_REVISIONS:
        pg.upgrade(fresh_db, revision)
        assert _rows(pg, fresh_db, "SELECT version_num FROM public.alembic_version") == {revision}


def test_all_schemas_tables_indexes_and_checks_exist(pg: Cluster, migrated_db: str) -> None:
    assert _rows(pg, migrated_db, "SELECT nspname FROM pg_namespace") >= SCHEMAS
    tables = _rows(
        pg,
        migrated_db,
        "SELECT schemaname || '.' || tablename FROM pg_tables WHERE schemaname IN "
        "('intel_raw', 'intel', 'agent', 'security', 'eval', 'ops')",
    )
    assert tables == TABLES
    indexes = _rows(
        pg,
        migrated_db,
        "SELECT indexname FROM pg_indexes WHERE indexname LIKE 'ix\\_%'",
    )
    assert indexes == EXPECTED_INDEXES
    checks = _rows(
        pg,
        migrated_db,
        "SELECT conname FROM pg_constraint WHERE contype = 'c' AND conname LIKE 'ck\\_%'",
    )
    assert checks == EXPECTED_CHECKS


def test_every_app_object_owned_by_nologin_owner(pg: Cluster, migrated_db: str) -> None:
    owners = _rows(
        pg,
        migrated_db,
        "SELECT DISTINCT pg_get_userbyid(c.relowner) FROM pg_class c "
        "JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname IN ('intel_raw', 'intel', 'agent', 'security', 'eval', 'ops')",
    )
    assert owners == {OWNER_ROLE}
    schema_owners = _rows(
        pg,
        migrated_db,
        "SELECT DISTINCT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname IN "
        "('intel_raw', 'intel', 'agent', 'security', 'eval', 'ops')",
    )
    assert schema_owners == {OWNER_ROLE}
    type_owners = _rows(
        pg,
        migrated_db,
        "SELECT DISTINCT pg_get_userbyid(t.typowner) FROM pg_type t JOIN pg_namespace n "
        "ON n.oid = t.typnamespace WHERE n.nspname = 'public' AND t.typtype IN ('e', 'd')",
    )
    assert type_owners == {OWNER_ROLE}


def test_roles_exist_with_expected_login_attributes(pg: Cluster, migrated_db: str) -> None:
    with pg.admin(migrated_db) as conn:
        fetched = conn.execute(
            "SELECT rolname, rolcanlogin FROM pg_roles WHERE rolname = ANY(%s)",
            ([OWNER_ROLE, *RUNTIME_ROLES],),
        ).fetchall()
    rows = {str(name): bool(can_login) for name, can_login in fetched}
    assert rows == {OWNER_ROLE: False, **dict.fromkeys(RUNTIME_ROLES, True)}


def test_role_bootstrap_is_idempotent(pg: Cluster, migrated_db: str) -> None:
    pg.init_roles(migrated_db)
    test_roles_exist_with_expected_login_attributes(pg, migrated_db)


def test_downgrade_each_step_then_reupgrade(pg: Cluster, fresh_db: str) -> None:
    pg.upgrade(fresh_db, "head")
    for revision in reversed(EXPECTED_REVISIONS[:-1]):
        pg.downgrade(fresh_db, revision)
        assert _rows(pg, fresh_db, "SELECT version_num FROM public.alembic_version") == {revision}
    pg.downgrade(fresh_db, "base")
    assert _rows(pg, fresh_db, "SELECT nspname FROM pg_namespace") & SCHEMAS == set()
    assert (
        _rows(
            pg,
            fresh_db,
            "SELECT typname FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace "
            "WHERE n.nspname = 'public' AND t.typtype IN ('e', 'd')",
        )
        == set()
    )
    pg.upgrade(fresh_db, "head")
    assert _rows(pg, fresh_db, "SELECT version_num FROM public.alembic_version") == {"0013"}
    with pg.admin(fresh_db) as conn:
        (held,) = conn.execute(  # type: ignore[misc]
            "SELECT has_table_privilege('ingest_writer', 'intel_raw.raw_ingest_record', 'INSERT')"
        ).fetchone()
        (public_connect,) = conn.execute(  # type: ignore[misc]
            "SELECT has_database_privilege('public', current_database(), 'CONNECT')"
        ).fetchone()
    assert held is True
    assert public_connect is False
