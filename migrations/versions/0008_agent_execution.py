"""agent.execution (PRD FR-015, FR-016, FR-031, FR-047; ARCHITECTURE.md §14, §21, §24).

- Version compatibility is enforced by composite foreign keys: the execution's
  fixture_set_version must be the scenario version's, and its
  tool_definitions_version must be the agent configuration's.
- run_role 'single' and 'protected' enforce the target policy.
- Lifecycle (FR-047) is separate from outcome; errored <=> error_class, and a
  termination_reason exists only for completed runs.
- execution_guard: an execution may only reference an approved scenario
  (FR-015); only the lifecycle/provisioning/as-run columns may change; the
  lifecycle moves forward only; terminal rows are frozen; rows cannot be
  deleted. Column-level UPDATE grants (0012) additionally restrict agent_svc.
- UNIQUE constraints on (id, ...) combinations let telemetry and replay tables
  prove, by composite foreign key, that they agree with their execution.

Revision ID: 0008
Revises: 0007
"""

from __future__ import annotations

from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None

# Columns agent-runtime may update (engineering plan §5.5, conflict C2).
MUTABLE_COLUMNS = (
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


def upgrade() -> None:
    mutable = ", ".join(f"'{column}'" for column in MUTABLE_COLUMNS)
    op.execute("""
    CREATE TABLE agent.execution (
        id uuid NOT NULL DEFAULT gen_random_uuid(),
        scenario_id uuid NOT NULL,
        scenario_version integer NOT NULL,
        agent_id text NOT NULL,
        agent_version integer NOT NULL,
        fixture_set_version public.version_label NOT NULL,
        tool_definitions_version public.version_label NOT NULL,
        sandbox_seed bigint NOT NULL,
        eval_config_version public.version_label NOT NULL,
        enforced_policy_id text NOT NULL,
        enforced_policy_version integer NOT NULL,
        target_policy_id text NOT NULL,
        target_policy_version integer NOT NULL,
        run_role public.run_role NOT NULL,
        locked_config jsonb NOT NULL,
        config_hash public.sha256_hex NOT NULL,
        lifecycle public.lifecycle NOT NULL DEFAULT 'pending',
        error_class public.error_class,
        termination_reason public.termination_reason,
        teardown_verified boolean,
        token_hash public.sha256_hex,
        sandbox_image_digest_as_run text,
        gateway_build_as_run text,
        fixture_checksum_as_run public.sha256_hex,
        queued_at timestamptz NOT NULL DEFAULT now(),
        started_at timestamptz,
        ended_at timestamptz,
        CONSTRAINT pk_execution PRIMARY KEY (id),
        CONSTRAINT fk_execution_scenario
            FOREIGN KEY (scenario_id, scenario_version, fixture_set_version)
            REFERENCES intel.scenario (scenario_id, version, fixture_set_version),
        CONSTRAINT fk_execution_agent_config
            FOREIGN KEY (agent_id, agent_version, tool_definitions_version)
            REFERENCES agent.agent_config (agent_id, version, tool_definitions_version),
        CONSTRAINT fk_execution_eval_config
            FOREIGN KEY (eval_config_version) REFERENCES eval.eval_config (version),
        CONSTRAINT fk_execution_enforced_policy
            FOREIGN KEY (enforced_policy_id, enforced_policy_version)
            REFERENCES security.policy (policy_id, version),
        CONSTRAINT fk_execution_target_policy
            FOREIGN KEY (target_policy_id, target_policy_version)
            REFERENCES security.policy (policy_id, version),
        CONSTRAINT uq_execution_policies UNIQUE (
            id, enforced_policy_id, enforced_policy_version,
            target_policy_id, target_policy_version
        ),
        CONSTRAINT uq_execution_replay_binding UNIQUE (
            id, run_role, config_hash, enforced_policy_id, enforced_policy_version,
            target_policy_id, target_policy_version
        ),
        CONSTRAINT uq_execution_eval_config UNIQUE (id, eval_config_version),
        CONSTRAINT ck_execution_enforces_target CHECK (
            run_role = 'baseline'
            OR (enforced_policy_id = target_policy_id
                AND enforced_policy_version = target_policy_version)
        ),
        CONSTRAINT ck_execution_error_class
            CHECK ((lifecycle = 'errored') = (error_class IS NOT NULL)),
        CONSTRAINT ck_execution_termination_reason
            CHECK (termination_reason IS NULL OR lifecycle = 'completed')
    );
    CREATE INDEX ix_execution_lifecycle_queued_at ON agent.execution (lifecycle, queued_at);
    CREATE INDEX ix_execution_scenario ON agent.execution (scenario_id, scenario_version);

    CREATE FUNCTION agent.execution_guard() RETURNS trigger
    LANGUAGE plpgsql AS $fn$
    DECLARE
        mutable text[] = ARRAY[""" + mutable + """];
    BEGIN
        IF TG_OP = 'INSERT' THEN
            IF NEW.lifecycle <> 'pending' THEN
                RAISE EXCEPTION 'execution must be inserted as pending' USING ERRCODE = 'AITL3';
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM intel.scenario s
                WHERE s.scenario_id = NEW.scenario_id
                  AND s.version = NEW.scenario_version
                  AND s.status = 'approved'
            ) THEN
                RAISE EXCEPTION 'execution requires an approved scenario version'
                    USING ERRCODE = 'AITL4';
            END IF;
            RETURN NEW;
        ELSIF TG_OP = 'UPDATE' THEN
            IF (to_jsonb(NEW) - mutable) IS DISTINCT FROM (to_jsonb(OLD) - mutable) THEN
                RAISE EXCEPTION 'execution configuration is immutable' USING ERRCODE = 'AITL2';
            END IF;
            IF OLD.lifecycle IN ('completed', 'errored', 'killed') THEN
                RAISE EXCEPTION 'terminal execution records are frozen' USING ERRCODE = 'AITL3';
            END IF;
            IF NOT (
                NEW.lifecycle = OLD.lifecycle
                OR (OLD.lifecycle = 'pending'
                    AND NEW.lifecycle IN ('running', 'errored', 'killed'))
                OR (OLD.lifecycle = 'running'
                    AND NEW.lifecycle IN ('completed', 'errored', 'killed'))
            ) THEN
                RAISE EXCEPTION 'invalid lifecycle transition % -> %', OLD.lifecycle, NEW.lifecycle
                    USING ERRCODE = 'AITL3';
            END IF;
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'execution records cannot be deleted' USING ERRCODE = 'AITL1';
    END;
    $fn$;

    CREATE TRIGGER trg_execution_guard
        BEFORE INSERT OR UPDATE OR DELETE ON agent.execution
        FOR EACH ROW EXECUTE FUNCTION agent.execution_guard();
    """)


def downgrade() -> None:
    op.execute("""
    DROP TABLE agent.execution;
    DROP FUNCTION agent.execution_guard();
    """)
