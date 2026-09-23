"""Schema-level security constraints (PRD FR-005a, FR-010c, FR-012, FR-015, FR-033a,
FR-044, FR-045a, FR-045d; ARCHITECTURE.md §24).

Every negative test requires an actual PostgreSQL constraint, trigger, or
privilege failure identified by SQLSTATE. Rows are written by the runtime role
that owns each write (tests/db_chain.py); owner-level attempts use the
migration owner via ``SET ROLE aitl_owner`` to prove the triggers hold even
against the schema owner.
"""

from __future__ import annotations

import json
import secrets
import uuid
from collections.abc import Iterator
from typing import Any

import psycopg
import pytest
from psycopg import errors

from tests import db_chain
from tests.db_chain import (
    BASELINE_POLICY,
    TARGET_POLICY,
    FullChain,
    execute,
    insert_scenario_sql,
    insert_sql,
    scenario_values,
)
from tests.pg_harness import OWNER_ROLE, Cluster

APPEND_ONLY = "AITL1"
IMMUTABLE = "AITL2"
BAD_TRANSITION = "AITL3"
UNAPPROVED = "AITL4"
FK = errors.ForeignKeyViolation.sqlstate
NOT_NULL = errors.NotNullViolation.sqlstate
CHECK = errors.CheckViolation.sqlstate
DENIED = errors.InsufficientPrivilege.sqlstate


@pytest.fixture(scope="module")
def db(pg: Cluster) -> Iterator[str]:
    name = f"aitl_constraints_{secrets.token_hex(4)}"
    pg.create_database(name)
    pg.upgrade(name)
    db_chain.load_configuration(pg, name)
    yield name
    pg.drop_database(name)


@pytest.fixture(scope="module")
def chain(pg: Cluster, db: str) -> FullChain:
    return db_chain.build_full_chain(pg, db, "synthetic")


@pytest.fixture(scope="module")
def honeypot_chain(pg: Cluster, db: str) -> FullChain:
    return db_chain.build_full_chain(pg, db, "honeypot")


def sqlstate_of(pg: Cluster, db: str, role: str, sql: str, params: Any = None) -> str | None:
    try:
        execute(pg, db, role, sql, params)
    except psycopg.Error as exc:
        return exc.sqlstate
    return None


def owner_sqlstate(pg: Cluster, db: str, sql: str, params: Any = None) -> str | None:
    """Attempt ``sql`` as the NOLOGIN owner (admin session with SET ROLE)."""
    with pg.admin(db) as conn:
        conn.autocommit = False
        try:
            conn.execute(f"SET ROLE {OWNER_ROLE}")
            conn.execute(sql, params)
        except psycopg.Error as exc:
            return exc.sqlstate
        finally:
            conn.rollback()
    return None


# --- Provenance chain (FR-045a) -------------------------------------------------------


def test_full_chain_resolves_to_origin_session(pg: Cluster, db: str, chain: FullChain) -> None:
    """From a policy decision back to the attack session via NOT NULL foreign keys only."""
    [(session_id, source_type)] = execute(
        pg,
        db,
        "eval_svc",
        "SELECT s.id, s.source_type FROM security.policy_decision d "
        "JOIN agent.execution e ON e.id = d.execution_id "
        "JOIN intel.scenario sc "
        "ON (sc.scenario_id, sc.version) = (e.scenario_id, e.scenario_version) "
        "JOIN intel.abstracted_threat_pattern p ON p.id = sc.threat_pattern_id "
        "JOIN intel.threat_pattern_source tps ON tps.pattern_id = p.id "
        "JOIN intel.ttp t ON t.id = tps.ttp_id "
        "JOIN intel.attacker_behavior b ON b.id = t.behavior_id "
        "JOIN intel.behavior_event be ON be.behavior_id = b.id "
        "JOIN intel.attack_event ev ON ev.id = be.event_id "
        "JOIN intel.attack_session s ON s.id = ev.session_id "
        "WHERE d.id = %s",
        (chain.decision_id,),
    )
    assert session_id == chain.intel.session_id
    assert source_type == "synthetic"


PROVENANCE_NOT_NULL = [
    ("intel", "attack_event", "session_id"),
    ("intel", "attack_event", "raw_record_id"),
    ("intel", "attacker_behavior", "session_id"),
    ("intel", "behavior_event", "behavior_id"),
    ("intel", "behavior_event", "event_id"),
    ("intel", "behavior_event", "session_id"),
    ("intel", "ttp", "behavior_id"),
    ("intel", "ttp", "session_id"),
    ("intel", "abstracted_threat_pattern", "session_id"),
    ("intel", "abstracted_threat_pattern", "source_type"),
    ("intel", "threat_pattern_source", "ttp_id"),
    ("intel", "threat_pattern_source", "pattern_id"),
    ("intel", "scenario", "threat_pattern_id"),
    ("intel", "scenario", "source_type"),
    ("agent", "execution", "scenario_id"),
    ("agent", "execution", "scenario_version"),
    ("security", "tool_invocation", "execution_id"),
    ("security", "policy_decision", "tool_invocation_id"),
    ("security", "policy_decision", "execution_id"),
    ("security", "trajectory", "execution_id"),
    ("eval", "blast_radius", "execution_id"),
    ("eval", "replay_run", "pair_id"),
    ("eval", "replay_run", "execution_id"),
    ("eval", "evaluation_result", "pair_id"),
]


@pytest.mark.parametrize(("schema", "table", "column"), PROVENANCE_NOT_NULL)
def test_provenance_columns_are_not_null(
    pg: Cluster, db: str, schema: str, table: str, column: str
) -> None:
    with pg.admin(db) as conn:
        row = conn.execute(
            "SELECT is_nullable FROM information_schema.columns "
            "WHERE table_schema = %s AND table_name = %s AND column_name = %s",
            (schema, table, column),
        ).fetchone()
    assert row == ("NO",)


def test_scenario_has_exactly_one_attack_origin_key(pg: Cluster, db: str) -> None:
    """FR-010c(a): the only attack-origin reference of a scenario is the threat pattern."""
    with pg.admin(db) as conn:
        rows = conn.execute(
            "SELECT DISTINCT cl.relnamespace::regnamespace::text || '.' || cl.relname "
            "FROM pg_constraint c JOIN pg_class cl ON cl.oid = c.confrelid "
            "WHERE c.conrelid = 'intel.scenario'::regclass AND c.contype = 'f'"
        ).fetchall()
        columns = conn.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = 'intel' AND table_name = 'scenario'"
        ).fetchall()
    referenced = {row[0] for row in rows}
    assert "intel.abstracted_threat_pattern" in referenced
    assert referenced.isdisjoint(
        {
            "intel.ttp",
            "intel.attacker_behavior",
            "intel.attack_event",
            "intel.attack_session",
            "intel_raw.raw_ingest_record",
        }
    )
    names = {row[0] for row in columns}
    assert names.isdisjoint({"ttp_id", "attack_event_id", "session_id", "source_reference"})


def test_scenario_without_threat_pattern_rejected(pg: Cluster, db: str, chain: FullChain) -> None:
    values = scenario_values(chain.intel.pattern_id, "synthetic", threat_pattern_id=None)
    assert sqlstate_of(pg, db, "scenario_gen", *insert_scenario_sql(values)) == NOT_NULL


def test_scenario_with_nonexistent_threat_pattern_rejected(pg: Cluster, db: str) -> None:
    values = scenario_values(uuid.uuid4(), "synthetic")
    assert sqlstate_of(pg, db, "scenario_gen", *insert_scenario_sql(values)) == FK


def test_synthetic_pattern_cannot_yield_honeypot_scenario(
    pg: Cluster, db: str, chain: FullChain
) -> None:
    """FR-045d: source_type is inherited; a scenario cannot relabel its origin."""
    values = scenario_values(chain.intel.pattern_id, "honeypot")
    assert sqlstate_of(pg, db, "scenario_gen", *insert_scenario_sql(values)) == FK


def test_honeypot_pattern_cannot_yield_synthetic_scenario(
    pg: Cluster, db: str, honeypot_chain: FullChain
) -> None:
    values = scenario_values(honeypot_chain.intel.pattern_id, "synthetic")
    assert sqlstate_of(pg, db, "scenario_gen", *insert_scenario_sql(values)) == FK


def test_pattern_cannot_relabel_its_session(pg: Cluster, db: str, chain: FullChain) -> None:
    state = sqlstate_of(
        pg,
        db,
        "intel_svc",
        "INSERT INTO intel.abstracted_threat_pattern (session_id, source_type, rule_id, "
        "abstraction_table_version, objective, target_tier, movement, tool_categories, tactics, "
        "techniques, rationale) VALUES (%s, 'honeypot', 'AR-9', 'v1', "
        "'access_above_authorized_tier', 'sensitive', 'none', "
        "ARRAY['read']::public.tool_category[], "
        "'{}', '{}', 'x')",
        (chain.intel.session_id,),
    )
    assert state == FK


def test_threat_pattern_source_cannot_cross_sessions(
    pg: Cluster, db: str, chain: FullChain, honeypot_chain: FullChain
) -> None:
    """ADR-016: a pattern's TTP chain comes from one session only."""
    for session in (chain.intel.session_id, honeypot_chain.intel.session_id):
        state = sqlstate_of(
            pg,
            db,
            "intel_svc",
            "INSERT INTO intel.threat_pattern_source (pattern_id, ordinal, ttp_id, session_id) "
            "VALUES (%s, 2, %s, %s)",
            (chain.intel.pattern_id, honeypot_chain.intel.ttp_id, session),
        )
        assert state == FK


def test_behavior_event_cannot_cross_sessions(
    pg: Cluster, db: str, chain: FullChain, honeypot_chain: FullChain
) -> None:
    state = sqlstate_of(
        pg,
        db,
        "intel_svc",
        "INSERT INTO intel.behavior_event (behavior_id, event_id, session_id) VALUES (%s, %s, %s)",
        (chain.intel.behavior_id, honeypot_chain.intel.event_id, chain.intel.session_id),
    )
    assert state == FK


def test_ttp_cannot_reference_another_sessions_behavior(
    pg: Cluster, db: str, chain: FullChain, honeypot_chain: FullChain
) -> None:
    state = sqlstate_of(
        pg,
        db,
        "intel_svc",
        "INSERT INTO intel.ttp (session_id, behavior_id, label, mapping_status, tactic_id, "
        "confidence, rule_id, ttp_rules_version, mapping_version, first_event_seq) VALUES "
        "(%s, %s, 'x', 'mapped', 'TA0006', 0.5, 'TR', 'v1', 'v1', 1)",
        (chain.intel.session_id, honeypot_chain.intel.behavior_id),
    )
    assert state == FK


def test_unmapped_ttp_has_no_tactic(pg: Cluster, db: str, chain: FullChain) -> None:
    state = sqlstate_of(
        pg,
        db,
        "intel_svc",
        "INSERT INTO intel.ttp (session_id, behavior_id, label, mapping_status, tactic_id, "
        "confidence, rule_id, ttp_rules_version, mapping_version, first_event_seq) VALUES "
        "(%s, %s, 'x', 'unmapped', 'TA0006', 0.5, 'TR', 'v1', 'v1', 1)",
        (chain.intel.session_id, chain.intel.behavior_id),
    )
    assert state == CHECK


# --- Scenario writer isolation (ADR-021; FR-010c) -------------------------------------------


def test_scenario_gen_can_insert_scenario_and_step(pg: Cluster, db: str, chain: FullChain) -> None:
    values = scenario_values(chain.intel.pattern_id, "synthetic")
    assert sqlstate_of(pg, db, "scenario_gen", *insert_scenario_sql(values)) is None
    step = (
        "INSERT INTO intel.scenario_step (scenario_id, version, ordinal, step_type, description) "
        "VALUES (%s, 1, 1, 'legitimate_task', 'read the task document')"
    )
    assert sqlstate_of(pg, db, "scenario_gen", step, (values["scenario_id"],)) is None


def test_intel_svc_cannot_insert_scenario(pg: Cluster, db: str, chain: FullChain) -> None:
    """A role that can read attacker text has no path to create a scenario."""
    values = scenario_values(chain.intel.pattern_id, "synthetic")
    assert sqlstate_of(pg, db, "intel_svc", *insert_scenario_sql(values)) == DENIED


def test_intel_svc_cannot_insert_scenario_step(pg: Cluster, db: str, chain: FullChain) -> None:
    state = sqlstate_of(
        pg,
        db,
        "intel_svc",
        "INSERT INTO intel.scenario_step (scenario_id, version, ordinal, step_type, description) "
        "VALUES (%s, 1, 99, 'injected', 'not allowed')",
        (chain.scenario_id,),
    )
    assert state == DENIED


@pytest.mark.parametrize(
    "role",
    ["ingest_writer", "intel_svc", "agent_svc", "gateway_svc", "eval_svc"],
)
def test_only_scenario_gen_writes_scenarios(
    pg: Cluster, db: str, chain: FullChain, role: str
) -> None:
    values = scenario_values(chain.intel.pattern_id, "synthetic")
    assert sqlstate_of(pg, db, role, *insert_scenario_sql(values)) == DENIED


@pytest.mark.parametrize(
    "table",
    [
        "intel_raw.raw_ingest_record",
        "intel_raw.quarantine_record",
        "intel.attack_session",
        "intel.attack_event",
        "intel.attacker_behavior",
        "intel.behavior_event",
        "intel.ttp",
        "intel.ttp_technique",
        "intel.threat_pattern_source",
    ],
)
def test_scenario_gen_cannot_read_attacker_derived_tables(
    pg: Cluster, db: str, chain: FullChain, table: str
) -> None:
    """Populated tables: the denial is a privilege failure, not an empty result."""
    assert sqlstate_of(pg, db, "scenario_gen", f"SELECT * FROM {table}") == DENIED


# --- Scenario immutability and review gate (FR-012, FR-015) ------------------------------


def test_scenario_must_start_generated(pg: Cluster, db: str, chain: FullChain) -> None:
    values = scenario_values(chain.intel.pattern_id, "synthetic", status="approved")
    assert sqlstate_of(pg, db, "scenario_gen", *insert_scenario_sql(values)) == BAD_TRANSITION


@pytest.mark.parametrize(
    ("path", "bad_next"),
    [
        ((), "approved"),  # skip review
        (("reviewed",), "generated"),  # backward
        (("reviewed", "approved"), "reviewed"),  # backward from approved
        (("rejected",), "approved"),  # resurrect rejected
        (("reviewed", "approved"), "rejected"),  # approved is final
    ],
)
def test_scenario_status_moves_forward_only(
    pg: Cluster, db: str, chain: FullChain, path: tuple[str, ...], bad_next: str
) -> None:
    scenario_id = db_chain.create_scenario(pg, db, chain.intel, approve=False)
    update = "UPDATE intel.scenario SET status = %s WHERE scenario_id = %s AND version = 1"
    for status in path:
        execute(pg, db, "intel_svc", update, (status, scenario_id))
    assert sqlstate_of(pg, db, "intel_svc", update, (bad_next, scenario_id)) == BAD_TRANSITION


def test_scenario_content_immutable_even_for_owner(pg: Cluster, db: str, chain: FullChain) -> None:
    assert (
        owner_sqlstate(
            pg,
            db,
            "UPDATE intel.scenario SET poisoned_content = 'changed' WHERE scenario_id = %s",
            (chain.scenario_id,),
        )
        == IMMUTABLE
    )
    assert (
        sqlstate_of(
            pg,
            db,
            "intel_svc",
            "UPDATE intel.scenario SET poisoned_content = 'changed' WHERE scenario_id = %s",
            (chain.scenario_id,),
        )
        == DENIED
    )


def test_scenario_cannot_be_deleted_or_truncated(pg: Cluster, db: str, chain: FullChain) -> None:
    assert (
        owner_sqlstate(
            pg, db, "DELETE FROM intel.scenario WHERE scenario_id = %s", (chain.scenario_id,)
        )
        == APPEND_ONLY
    )
    assert owner_sqlstate(pg, db, "TRUNCATE intel.scenario CASCADE") == APPEND_ONLY


# --- Execution: approval, version compatibility, lifecycle (FR-015, FR-031, FR-047) --------


def test_execution_requires_approved_scenario(pg: Cluster, db: str, chain: FullChain) -> None:
    unapproved = db_chain.create_scenario(pg, db, chain.intel, approve=False)
    values = db_chain.execution_values(unapproved)
    assert sqlstate_of(pg, db, "agent_svc", *insert_sql("agent.execution", values)) == UNAPPROVED


@pytest.mark.parametrize(
    "overrides",
    [
        {"fixture_set_version": "v2"},  # fixture set differs from the scenario's
        {"tool_definitions_version": "v9"},  # tool definitions differ from the agent config's
        {"agent_version": 99},
        {"eval_config_version": "eval-v9"},
        {"target_policy_id": "nonexistent", "enforced_policy_id": "nonexistent"},
    ],
    ids=["fixture-set", "tool-defs", "agent", "eval-config", "policy"],
)
def test_execution_with_incompatible_versions_rejected(
    pg: Cluster, db: str, chain: FullChain, overrides: dict[str, Any]
) -> None:
    values = db_chain.execution_values(chain.scenario_id, **overrides)
    assert sqlstate_of(pg, db, "agent_svc", *insert_sql("agent.execution", values)) == FK


def test_execution_of_nonexistent_scenario_version_rejected(
    pg: Cluster, db: str, chain: FullChain
) -> None:
    """The approval guard runs first: a version that does not exist is not approved."""
    values = db_chain.execution_values(chain.scenario_id, scenario_version=2)
    assert sqlstate_of(pg, db, "agent_svc", *insert_sql("agent.execution", values)) == UNAPPROVED


@pytest.mark.parametrize("run_role", ["single", "protected"])
def test_single_and_protected_runs_enforce_target(
    pg: Cluster, db: str, chain: FullChain, run_role: str
) -> None:
    values = db_chain.execution_values(
        chain.scenario_id,
        run_role=run_role,
        enforced_policy_id=BASELINE_POLICY[0],
        enforced_policy_version=BASELINE_POLICY[1],
    )
    assert sqlstate_of(pg, db, "agent_svc", *insert_sql("agent.execution", values)) == CHECK


def test_execution_must_start_pending(pg: Cluster, db: str, chain: FullChain) -> None:
    values = db_chain.execution_values(chain.scenario_id, lifecycle="completed")
    assert (
        sqlstate_of(pg, db, "agent_svc", *insert_sql("agent.execution", values)) == BAD_TRANSITION
    )


def _lifecycle(pg: Cluster, db: str, execution_id: uuid.UUID, **columns: Any) -> str | None:
    assignments = ", ".join(f"{name} = %s" for name in columns)
    return sqlstate_of(
        pg,
        db,
        "agent_svc",
        f"UPDATE agent.execution SET {assignments} WHERE id = %s",
        (*columns.values(), execution_id),
    )


def test_execution_lifecycle_forward_and_terminal_frozen(
    pg: Cluster, db: str, chain: FullChain
) -> None:
    execution_id = db_chain.create_execution(pg, db, chain.scenario_id)
    assert _lifecycle(pg, db, execution_id, lifecycle="completed") == BAD_TRANSITION
    assert _lifecycle(pg, db, execution_id, token_hash=db_chain.sha("token")) is None
    assert _lifecycle(pg, db, execution_id, lifecycle="running") is None
    assert _lifecycle(pg, db, execution_id, lifecycle="pending") == BAD_TRANSITION
    assert _lifecycle(pg, db, execution_id, lifecycle="errored") == CHECK  # needs error_class
    assert (
        _lifecycle(pg, db, execution_id, lifecycle="completed", termination_reason="agent_finished")
        is None
    )
    assert _lifecycle(pg, db, execution_id, teardown_verified=True) == BAD_TRANSITION
    assert _lifecycle(pg, db, execution_id, lifecycle="errored", error_class="timeout") == (
        BAD_TRANSITION
    )


def test_execution_configuration_immutable(pg: Cluster, db: str, chain: FullChain) -> None:
    execution_id = db_chain.create_execution(pg, db, chain.scenario_id)
    assert _lifecycle(pg, db, execution_id, sandbox_seed=8) == DENIED  # not in column grant
    assert (
        owner_sqlstate(
            pg, db, "UPDATE agent.execution SET sandbox_seed = 8 WHERE id = %s", (execution_id,)
        )
        == IMMUTABLE
    )
    assert (
        owner_sqlstate(pg, db, "DELETE FROM agent.execution WHERE id = %s", (execution_id,))
        == APPEND_ONLY
    )


# --- Telemetry binding (FR-018, FR-022, FR-027) ----------------------------------------------


def test_decision_must_name_executions_policies_and_loaded_hash(
    pg: Cluster, db: str, chain: FullChain
) -> None:
    execution_id = chain.execution_id
    invocation_id = db_chain.create_tool_invocation(pg, db, execution_id, 50)
    cases = [
        {"enforced_policy_id": BASELINE_POLICY[0]},  # not this execution's enforced policy
        {"target_content_sha256": db_chain.sha("tampered")},  # not the loaded content
        {"enforced_content_sha256": db_chain.BASELINE_SHA},
    ]
    for overrides in cases:
        values = db_chain.policy_decision_values(execution_id, invocation_id, 51, **overrides)
        state = sqlstate_of(pg, db, "gateway_svc", *insert_sql("security.policy_decision", values))
        assert state == FK, overrides


def test_decision_cannot_attach_to_another_executions_invocation(
    pg: Cluster, db: str, chain: FullChain, honeypot_chain: FullChain
) -> None:
    foreign_invocation = db_chain.create_tool_invocation(pg, db, honeypot_chain.execution_id, 60)
    values = db_chain.policy_decision_values(chain.execution_id, foreign_invocation, 60)
    assert sqlstate_of(pg, db, "gateway_svc", *insert_sql("security.policy_decision", values)) == FK


def test_unevaluated_requests_must_be_denied(pg: Cluster, db: str, chain: FullChain) -> None:
    """NFR-006: system errors, validation failures, and step limits can only DENY."""
    invocation_id = db_chain.create_tool_invocation(pg, db, chain.execution_id, 70)
    values = db_chain.policy_decision_values(
        chain.execution_id,
        invocation_id,
        71,
        reason_code="system_error",
        enforced_permission=None,
        enforced_dataflow=None,
        target_permission=None,
        target_dataflow=None,
        enforced_final="ALLOW",
    )
    assert (
        sqlstate_of(pg, db, "gateway_svc", *insert_sql("security.policy_decision", values)) == CHECK
    )


def test_step_sequence_unique_per_execution(pg: Cluster, db: str, chain: FullChain) -> None:
    state = sqlstate_of(
        pg,
        db,
        "gateway_svc",
        "INSERT INTO security.tool_invocation (execution_id, seq, received_at, tool, "
        "raw_args_sha256, validation_status, rejection_reason) VALUES "
        "(%s, 1, now(), 'file_read', %s, 'rejected', 'duplicate seq')",
        (chain.execution_id, db_chain.sha("dup")),
    )
    assert state == errors.UniqueViolation.sqlstate


def test_undispatched_result_carries_no_content(pg: Cluster, db: str, chain: FullChain) -> None:
    invocation_id = db_chain.create_tool_invocation(pg, db, chain.execution_id, 80)
    state = sqlstate_of(
        pg,
        db,
        "gateway_svc",
        "INSERT INTO security.tool_result (execution_id, seq, tool_invocation_id, dispatched, "
        "result, returned_asset_ids, completed_at) VALUES (%s, 81, %s, false, '{\"leak\": 1}', "
        "ARRAY['sensitive-deploy-credentials'], now())",
        (chain.execution_id, invocation_id),
    )
    assert state == CHECK


# --- Replay pairing (FR-033a, FR-033b) and evaluation --------------------------------------


def _new_pair(pg: Cluster, db: str, scenario_id: uuid.UUID) -> tuple[uuid.UUID, str, str]:
    locked = {"scenario": str(scenario_id), "seed": secrets.randbelow(10**6)}
    config_hash = db_chain.sha(locked)
    pair_id = uuid.uuid4()
    execute(
        pg,
        db,
        "eval_svc",
        "INSERT INTO eval.replay_pair (id, scenario_id, scenario_version, locked_config, "
        "config_hash, baseline_policy_id, baseline_policy_version, target_policy_id, "
        "target_policy_version, eval_config_version, repetitions) "
        "VALUES (%s, %s, 1, %s, %s, %s, %s, %s, %s, %s, 2)",
        (
            pair_id,
            scenario_id,
            json.dumps(locked),
            config_hash,
            *BASELINE_POLICY,
            *TARGET_POLICY,
            db_chain.EVAL_CONFIG,
        ),
    )
    return pair_id, config_hash, json.dumps(locked)


def test_pair_rejects_execution_with_drifted_configuration(
    pg: Cluster, db: str, chain: FullChain
) -> None:
    pair_id, config_hash, _locked = _new_pair(pg, db, chain.scenario_id)
    drifted = db_chain.create_execution(
        pg,
        db,
        chain.scenario_id,
        run_role="protected",
        locked_config=json.dumps({"x": 1}),
        config_hash=db_chain.sha({"x": 1}),
    )
    values = db_chain.replay_run_values(
        pair_id, drifted, "protected", 0, config_hash, TARGET_POLICY
    )
    assert sqlstate_of(pg, db, "eval_svc", *insert_sql("eval.replay_run", values)) == FK


def test_pair_rejects_arm_with_wrong_role_or_policy(pg: Cluster, db: str, chain: FullChain) -> None:
    pair_id, config_hash, locked = _new_pair(pg, db, chain.scenario_id)
    protected = db_chain.create_execution(
        pg,
        db,
        chain.scenario_id,
        run_role="protected",
        locked_config=locked,
        config_hash=config_hash,
    )
    # Registering a protected execution as the baseline arm.
    values = db_chain.replay_run_values(
        pair_id, protected, "baseline", 0, config_hash, TARGET_POLICY
    )
    assert sqlstate_of(pg, db, "eval_svc", *insert_sql("eval.replay_run", values)) == CHECK
    values = db_chain.replay_run_values(
        pair_id, protected, "baseline", 0, config_hash, BASELINE_POLICY
    )
    assert sqlstate_of(pg, db, "eval_svc", *insert_sql("eval.replay_run", values)) == FK
    # A baseline arm that secretly used a different target policy.
    other_target = db_chain.create_execution(
        pg,
        db,
        chain.scenario_id,
        run_role="baseline",
        locked_config=locked,
        config_hash=config_hash,
        enforced_policy_id=BASELINE_POLICY[0],
        enforced_policy_version=BASELINE_POLICY[1],
        target_policy_id=BASELINE_POLICY[0],
        target_policy_version=BASELINE_POLICY[1],
    )
    values = db_chain.replay_run_values(
        pair_id, other_target, "baseline", 0, config_hash, BASELINE_POLICY
    )
    assert sqlstate_of(pg, db, "eval_svc", *insert_sql("eval.replay_run", values)) == FK


def test_pair_arm_registered_once(pg: Cluster, db: str, chain: FullChain) -> None:
    pair_id, config_hash, locked = _new_pair(pg, db, chain.scenario_id)
    first = db_chain.create_execution(
        pg,
        db,
        chain.scenario_id,
        run_role="protected",
        locked_config=locked,
        config_hash=config_hash,
    )
    second = db_chain.create_execution(
        pg,
        db,
        chain.scenario_id,
        run_role="protected",
        locked_config=locked,
        config_hash=config_hash,
    )
    execute(
        pg,
        db,
        "eval_svc",
        *insert_sql(
            "eval.replay_run",
            db_chain.replay_run_values(pair_id, first, "protected", 0, config_hash, TARGET_POLICY),
        ),
    )
    values = db_chain.replay_run_values(pair_id, second, "protected", 1, config_hash, TARGET_POLICY)
    state = sqlstate_of(pg, db, "eval_svc", *insert_sql("eval.replay_run", values))
    assert state == errors.UniqueViolation.sqlstate


def test_blast_radius_uses_executions_eval_config(pg: Cluster, db: str, chain: FullChain) -> None:
    execute(
        pg,
        db,
        "eval_svc",
        "INSERT INTO eval.eval_config (version, weights, thresholds, content_sha256) "
        "VALUES ('eval-v2', '{}', '[]', %s)",
        (db_chain.sha("eval-v2"),),
    )
    state = sqlstate_of(
        pg,
        db,
        "eval_svc",
        "INSERT INTO eval.blast_radius (execution_id, eval_config_version, u_attempted, u_allowed, "
        "r_public, r_private, r_sensitive, x_attempted, x_succeeded, v, tool_calls, legit_calls, "
        "false_blocks, score, label, attack_attempted, attack_succeeded, task_succeeded, "
        "had_enforced_deny) VALUES (%s, 'eval-v2', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 'MINIMAL', "
        "false, false, true, false)",
        (chain.protected_execution_id,),
    )
    assert state == FK


def test_blast_radius_blocked_attempts_are_not_impact(
    pg: Cluster, db: str, chain: FullChain
) -> None:
    """FR-029: allowed-unauthorized calls are a subset of attempts; exfil success <= attempt."""
    for u_attempted, u_allowed, x_attempted, x_succeeded in ((0, 1, 0, 0), (1, 0, 0, 1)):
        state = sqlstate_of(
            pg,
            db,
            "eval_svc",
            "INSERT INTO eval.blast_radius (execution_id, eval_config_version, u_attempted, "
            "u_allowed, r_public, r_private, r_sensitive, x_attempted, x_succeeded, v, tool_calls, "
            "legit_calls, false_blocks, score, label, attack_attempted, attack_succeeded, "
            "task_succeeded, had_enforced_deny) VALUES (%s, %s, %s, %s, 0, 0, 0, %s, %s, 0, 5, 0, "
            "0, 0, 'MINIMAL', false, false, true, false)",
            (
                chain.baseline_execution_id,
                db_chain.EVAL_CONFIG,
                u_attempted,
                u_allowed,
                x_attempted,
                x_succeeded,
            ),
        )
        assert state == CHECK


def test_evaluation_result_counts_match_pair(pg: Cluster, db: str, chain: FullChain) -> None:
    pair_id, _, _ = _new_pair(pg, db, chain.scenario_id)  # repetitions = 2
    state = sqlstate_of(
        pg,
        db,
        "eval_svc",
        "INSERT INTO eval.evaluation_result (pair_id, validity, n_requested, n_valid, n_excluded, "
        "single_observation, limitation_disclosure) VALUES (%s, 'valid', 3, 3, 0, false, 'x')",
        (pair_id,),
    )
    assert state == FK


# --- Append-only enforcement for every role, including the owner (FR-044) ------------------

APPEND_ONLY_TABLES = [
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
    "intel.scenario_step",
    "agent.agent_config",
    "agent.agent_task",
    "agent.tool",
    "agent.data_asset",
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
]


def _first_mutable_column(pg: Cluster, db: str, table: str) -> str:
    schema, name = table.split(".")
    with pg.admin(db) as conn:
        row = conn.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_schema = %s "
            "AND table_name = %s AND is_identity = 'NO' ORDER BY ordinal_position LIMIT 1",
            (schema, name),
        ).fetchone()
    assert row is not None
    return str(row[0])


@pytest.mark.parametrize("table", APPEND_ONLY_TABLES)
def test_owner_cannot_update_delete_or_truncate(
    pg: Cluster, db: str, chain: FullChain, table: str
) -> None:
    """Triggers hold even for the schema owner (grants alone would not)."""
    column = _first_mutable_column(pg, db, table)
    assert owner_sqlstate(pg, db, f"UPDATE {table} SET {column} = {column}") == APPEND_ONLY
    assert owner_sqlstate(pg, db, f"DELETE FROM {table}") == APPEND_ONLY
    assert owner_sqlstate(pg, db, f"TRUNCATE {table} CASCADE") == APPEND_ONLY


def test_append_only_rows_actually_exist(pg: Cluster, db: str, chain: FullChain) -> None:
    """Guard for the test above: the chain populated the telemetry tables it protects."""
    for table in (
        "security.policy_decision",
        "security.trajectory",
        "eval.replay_run",
        "intel.attack_event",
        "eval.evaluation_result",
    ):
        [(count,)] = execute(
            pg,
            db,
            "eval_svc" if not table.startswith("intel") else "intel_svc",
            f"SELECT count(*) FROM {table}",
        )
        assert count >= 1, table


def test_append_only_trigger_set_is_complete(pg: Cluster, db: str) -> None:
    with pg.admin(db) as conn:
        rows = conn.execute(
            "SELECT c.relnamespace::regnamespace::text || '.' || c.relname, t.tgname "
            "FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid WHERE NOT t.tgisinternal"
        ).fetchall()
    triggers: dict[str, set[str]] = {}
    for table, name in rows:
        triggers.setdefault(str(table), set()).add(str(name))
    for table in APPEND_ONLY_TABLES:
        short = table.split(".")[1]
        assert {f"trg_{short}_append_only", f"trg_{short}_no_truncate"} <= triggers[table], table
    assert {"trg_scenario_guard", "trg_scenario_no_truncate"} <= triggers["intel.scenario"]
    assert {"trg_execution_guard", "trg_execution_no_truncate"} <= triggers["agent.execution"]


# --- Attacker-derived data typing and caps (FR-005a, FR-013) --------------------------------

UNTRUSTED_COLUMNS = {
    ("intel_raw", "raw_ingest_record", "payload"),
    ("intel_raw", "quarantine_record", "payload"),
    ("intel", "attack_session", "cowrie_session_id"),
    ("intel", "attack_event", "raw_text"),
    ("intel", "attack_event", "normalized_text"),
    ("intel", "attack_event", "username"),
    ("intel", "attack_event", "attempted_secret"),
    ("security", "agent_final_response", "text"),
    ("security", "agent_final_response", "normalized_text"),
}


def test_untrusted_text_domain_on_exactly_the_untrusted_columns(pg: Cluster, db: str) -> None:
    with pg.admin(db) as conn:
        rows = conn.execute(
            "SELECT table_schema, table_name, column_name FROM information_schema.columns "
            "WHERE domain_name = 'untrusted_text'"
        ).fetchall()
    assert {tuple(row) for row in rows} == UNTRUSTED_COLUMNS


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("raw_text", "x" * 4097),
        ("raw_text", "é" * 2049),  # 4098 bytes
        ("normalized_text", "x" * 1025),
        ("username", "u" * 257),
        ("attempted_secret", "p" * 257),
    ],
)
def test_attack_event_field_caps(
    pg: Cluster, db: str, chain: FullChain, column: str, value: str
) -> None:
    fields = {
        "session_id": chain.intel.session_id,
        "raw_record_id": chain.intel.raw_record_id,
        "seq": 99,
        "event_type": "command_input",
        "occurred_at": "2026-01-01T00:00:00Z",
        "raw_text": "ls",
        "normalized_text": "ls",
        "truncated": False,
    }
    fields[column] = value
    assert sqlstate_of(pg, db, "intel_svc", *insert_sql("intel.attack_event", fields)) == CHECK


def test_untrusted_domain_cap(pg: Cluster, db: str) -> None:
    state = sqlstate_of(
        pg,
        db,
        "ingest_writer",
        "INSERT INTO intel_raw.raw_ingest_record (kind, ingest_mode, source_ref, payload, "
        "payload_sha256) VALUES ('event', 'fixture', 'x', %s, %s)",
        ("x" * 65537, db_chain.sha("big")),
    )
    assert state == CHECK


def test_raw_payload_preserved_verbatim(pg: Cluster, db: str) -> None:
    """Persistence does not rewrite attacker evidence; sanitization is the Shipper's job."""
    hostile = "rm -rf / ; echo $'\\x1b[31m' ; `id` ; '; DROP TABLE x; --"
    ref = f"verbatim:{secrets.token_hex(4)}"
    execute(
        pg,
        db,
        "ingest_writer",
        "INSERT INTO intel_raw.raw_ingest_record (kind, ingest_mode, source_ref, payload, "
        "payload_sha256) VALUES ('event', 'fixture', %s, %s, %s)",
        (ref, hostile, db_chain.sha(hostile)),
    )
    [(stored,)] = execute(
        pg,
        db,
        "intel_svc",
        "SELECT payload FROM intel_raw.raw_ingest_record WHERE source_ref = %s",
        (ref,),
    )
    assert stored == hostile


@pytest.mark.parametrize(
    ("tool", "endpoint"),
    [("mock_api", ""), ("mock_api", "http_get"), ("file_read", "send_message")],
)
def test_tool_endpoints_are_enumerated(pg: Cluster, db: str, tool: str, endpoint: str) -> None:
    """FR-002: only mock_api has endpoints, and only directory_lookup/send_message."""
    state = sqlstate_of(
        pg,
        db,
        "agent_svc",
        "INSERT INTO agent.tool (tool_definitions_version, tool_name, endpoint, destination_trust, "
        "argument_schema, content_sha256) VALUES ('v7', %s, %s, 'external', '{}', %s)",
        (tool, endpoint, db_chain.sha(endpoint)),
    )
    assert state == CHECK


def test_unknown_tool_name_rejected(pg: Cluster, db: str) -> None:
    state = sqlstate_of(
        pg,
        db,
        "agent_svc",
        "INSERT INTO agent.tool (tool_definitions_version, tool_name, endpoint, destination_trust, "
        "argument_schema, content_sha256) VALUES ('v7', 'shell_exec', '', 'internal', '{}', %s)",
        (db_chain.sha("shell"),),
    )
    assert state == errors.InvalidTextRepresentation.sqlstate


def test_non_public_assets_must_carry_markers(pg: Cluster, db: str) -> None:
    state = sqlstate_of(
        pg,
        db,
        "agent_svc",
        "INSERT INTO agent.data_asset (fixture_set_version, asset_id, kind, locator, tier, "
        "has_markers, content_sha256) VALUES ('v7', 'a', 'file', '/sensitive/a', 'sensitive', "
        "false, %s)",
        (db_chain.sha("a"),),
    )
    assert state == CHECK
