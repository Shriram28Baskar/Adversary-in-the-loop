"""Runtime grants and append-only enforcement (ARCHITECTURE.md §24; PRD FR-044, FR-033d).

Layer 1 — privileges. PUBLIC gets nothing: no CONNECT/TEMP on the database, no
usage of the public schema, types, domains, or functions, no table access.
Each runtime role receives exactly the §24 grants (plus the engineering-plan
§5.5 additions), and no role receives UPDATE, DELETE, or TRUNCATE on any
append-only table. The only UPDATE grants are column-level:
intel_svc -> intel.scenario(status) and agent_svc -> the agent.execution
lifecycle/provisioning/as-run columns.

Layer 2 — triggers. Every append-only table gets statement-level triggers that
reject UPDATE, DELETE, and TRUNCATE for every role, including the owner.
intel.scenario and agent.execution keep their row-level guards (0007, 0008)
and additionally reject TRUNCATE.

Grants not literally listed in ARCHITECTURE.md §24 but required by it:
- intel_svc SELECT on intel.* (it reads what it writes; UPDATE(status) needs it).
- gateway_svc SELECT on security.policy (§17: a changed policy file with an
  existing version must be detected at startup).
Engineering-plan §5.5 additions for agent_svc lifecycle derivation (conflict C1):
SELECT on security.policy, eval.eval_config, security.system_failure_event,
security.model_call, security.policy_decision.

Revision ID: 0012
Revises: 0011
"""

from __future__ import annotations

from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None

RUNTIME_ROLES = ("ingest_writer", "intel_svc", "scenario_gen", "agent_svc", "gateway_svc", "eval_svc")
SCHEMAS = ("intel_raw", "intel", "agent", "security", "eval", "ops")

EXECUTION_MUTABLE_COLUMNS = (
    "lifecycle",
    "error_class",
    "termination_reason",
    "teardown_verified",
    "token_hash",
    "sandbox_image_digest_as_run",
    "gateway_build_as_run",
    "fixture_checksum_as_run",
    "started_at",
    "ended_at",
)

GRANTS: dict[str, tuple[str, ...]] = {
    "ingest_writer": (
        "GRANT USAGE ON SCHEMA intel_raw TO ingest_writer",
        "GRANT INSERT ON intel_raw.raw_ingest_record, intel_raw.quarantine_record "
        "TO ingest_writer",
    ),
    "intel_svc": (
        "GRANT USAGE ON SCHEMA intel_raw, intel, agent, security, eval, ops TO intel_svc",
        "GRANT SELECT ON ALL TABLES IN SCHEMA intel_raw TO intel_svc",
        "GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA intel TO intel_svc",
        "GRANT INSERT ON intel_raw.quarantine_record TO intel_svc",
        "GRANT INSERT ON ops.events TO intel_svc",
        "GRANT UPDATE (status) ON intel.scenario TO intel_svc",
        "GRANT SELECT ON ALL TABLES IN SCHEMA agent, security, eval TO intel_svc",
    ),
    "scenario_gen": (
        "GRANT USAGE ON SCHEMA intel, agent TO scenario_gen",
        "GRANT SELECT ON intel.abstracted_threat_pattern, intel.scenario, "
        "agent.agent_task, agent.data_asset TO scenario_gen",
        "GRANT INSERT ON intel.scenario, intel.scenario_step TO scenario_gen",
    ),
    "agent_svc": (
        "GRANT USAGE ON SCHEMA intel, agent, security, eval, ops TO agent_svc",
        "GRANT SELECT ON intel.scenario TO agent_svc",
        "GRANT SELECT ON ALL TABLES IN SCHEMA agent TO agent_svc",
        "GRANT INSERT ON agent.execution, agent.agent_config, agent.agent_task, agent.tool, "
        "agent.data_asset TO agent_svc",
        "GRANT INSERT ON ops.events TO agent_svc",
        f"GRANT UPDATE ({', '.join(EXECUTION_MUTABLE_COLUMNS)}) ON agent.execution TO agent_svc",
        "GRANT SELECT ON security.policy, eval.eval_config, security.system_failure_event, "
        "security.model_call, security.policy_decision TO agent_svc",
    ),
    "gateway_svc": (
        "GRANT USAGE ON SCHEMA intel, agent, security, ops TO gateway_svc",
        "GRANT SELECT ON ALL TABLES IN SCHEMA agent TO gateway_svc",
        "GRANT SELECT ON intel.scenario, intel.scenario_step TO gateway_svc",
        "GRANT INSERT ON security.policy, security.tool_invocation, security.policy_decision, "
        "security.tool_result, security.data_flow_event, security.security_violation, "
        "security.system_failure_event, security.model_call, security.agent_final_response "
        "TO gateway_svc",
        "GRANT SELECT ON security.policy TO gateway_svc",
        "GRANT INSERT ON ops.events TO gateway_svc",
    ),
    "eval_svc": (
        "GRANT USAGE ON SCHEMA intel, agent, security, eval, ops TO eval_svc",
        "GRANT SELECT ON ALL TABLES IN SCHEMA intel, agent, security, eval TO eval_svc",
        "GRANT INSERT ON security.trajectory TO eval_svc",
        "GRANT INSERT ON ALL TABLES IN SCHEMA eval TO eval_svc",
        "GRANT INSERT ON ops.events TO eval_svc",
    ),
}

# FR-044 plus the join/step/outbox tables whose parents are immutable.
APPEND_ONLY_TABLES = (
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
)
GUARDED_TABLES = ("intel.scenario", "agent.execution")

TYPES = (
    "untrusted_text",
    "sha256_hex",
    "version_label",
)


def _trigger_name(table: str, suffix: str) -> str:
    return f"trg_{table.split('.')[1]}_{suffix}"


def upgrade() -> None:
    roles = ", ".join(RUNTIME_ROLES)
    schemas = ", ".join(SCHEMAS)

    # PUBLIC gets nothing.
    op.execute(
        "DO $$ BEGIN "
        "EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database()); "
        f"EXECUTE format('GRANT CONNECT ON DATABASE %I TO {roles}', current_database()); "
        "END $$"
    )
    op.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
    op.execute(f"REVOKE ALL ON SCHEMA {schemas} FROM PUBLIC")
    op.execute(f"REVOKE ALL ON ALL TABLES IN SCHEMA public, {schemas} FROM PUBLIC")
    op.execute(f"REVOKE ALL ON ALL SEQUENCES IN SCHEMA public, {schemas} FROM PUBLIC")
    op.execute(f"REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public, {schemas} FROM PUBLIC")
    op.execute(
        "DO $$ DECLARE t record; BEGIN "
        "FOR t IN SELECT format('%I.%I', n.nspname, ty.typname) AS name FROM pg_type ty "
        "JOIN pg_namespace n ON n.oid = ty.typnamespace "
        "WHERE n.nspname = 'public' AND ty.typtype IN ('e', 'd') LOOP "
        "EXECUTE 'REVOKE ALL ON TYPE ' || t.name || ' FROM PUBLIC'; "
        "EXECUTE 'GRANT USAGE ON TYPE ' || t.name || ' TO " + roles + "'; "
        "END LOOP; END $$"
    )
    op.execute(f"GRANT USAGE ON SCHEMA public TO {roles}")

    for statements in GRANTS.values():
        for statement in statements:
            op.execute(statement)

    op.execute("""
    CREATE FUNCTION public.aitl_forbid_mutation() RETURNS trigger
    LANGUAGE plpgsql AS $fn$
    BEGIN
        RAISE EXCEPTION '%.% is append-only: % is not permitted', TG_TABLE_SCHEMA, TG_TABLE_NAME, TG_OP
            USING ERRCODE = 'AITL1';
    END;
    $fn$
    """)
    op.execute("REVOKE ALL ON FUNCTION public.aitl_forbid_mutation() FROM PUBLIC")
    for table in APPEND_ONLY_TABLES:
        op.execute(
            f"CREATE TRIGGER {_trigger_name(table, 'append_only')} "
            f"BEFORE UPDATE OR DELETE ON {table} "
            "FOR EACH STATEMENT EXECUTE FUNCTION public.aitl_forbid_mutation()"
        )
    for table in (*APPEND_ONLY_TABLES, *GUARDED_TABLES):
        op.execute(
            f"CREATE TRIGGER {_trigger_name(table, 'no_truncate')} "
            f"BEFORE TRUNCATE ON {table} "
            "FOR EACH STATEMENT EXECUTE FUNCTION public.aitl_forbid_mutation()"
        )


def downgrade() -> None:
    roles = ", ".join(RUNTIME_ROLES)
    schemas = ", ".join(SCHEMAS)
    for table in (*APPEND_ONLY_TABLES, *GUARDED_TABLES):
        op.execute(f"DROP TRIGGER {_trigger_name(table, 'no_truncate')} ON {table}")
    for table in APPEND_ONLY_TABLES:
        op.execute(f"DROP TRIGGER {_trigger_name(table, 'append_only')} ON {table}")
    op.execute("DROP FUNCTION public.aitl_forbid_mutation()")

    op.execute(f"REVOKE ALL ON ALL TABLES IN SCHEMA {schemas} FROM {roles}")
    op.execute(f"REVOKE ALL ON SCHEMA public, {schemas} FROM {roles}")
    op.execute(
        "DO $$ DECLARE t record; BEGIN "
        "FOR t IN SELECT format('%I.%I', n.nspname, ty.typname) AS name FROM pg_type ty "
        "JOIN pg_namespace n ON n.oid = ty.typnamespace "
        "WHERE n.nspname = 'public' AND ty.typtype IN ('e', 'd') LOOP "
        "EXECUTE 'REVOKE ALL ON TYPE ' || t.name || ' FROM " + roles + "'; "
        "EXECUTE 'GRANT USAGE ON TYPE ' || t.name || ' TO PUBLIC'; "
        "END LOOP; END $$"
    )
    # Restore PostgreSQL's default PUBLIC privileges.
    op.execute(f"GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public, {schemas} TO PUBLIC")
    op.execute("GRANT USAGE ON SCHEMA public TO PUBLIC")
    op.execute(
        "DO $$ BEGIN "
        f"EXECUTE format('REVOKE CONNECT ON DATABASE %I FROM {roles}', current_database()); "
        "EXECUTE format('GRANT CONNECT, TEMPORARY ON DATABASE %I TO PUBLIC', current_database()); "
        "END $$"
    )
