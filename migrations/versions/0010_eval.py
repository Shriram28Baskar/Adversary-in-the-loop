"""Evaluation tables (PRD FR-029–FR-030a, FR-031–FR-034, FR-045; ARCHITECTURE.md §20–§22).

Structural single-variable control (FR-033a): a replay_run row carries the
pair's locked config hash and policy versions, and composite foreign keys
require them to match both the pair and the referenced execution. The
enforced-policy check ties each arm to its policy (baseline arm enforces the
pair's baseline policy; protected arm enforces the target). So a pair cannot
contain an execution whose configuration or policies differ from the lock.

blast_radius is keyed by execution and must use the execution's EvalConfig
version (FR-029a). evaluation_result's n_requested must equal the pair's
repetitions.

Revision ID: 0010
Revises: 0009
"""

from __future__ import annotations

from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE eval.replay_pair (
        id uuid NOT NULL DEFAULT gen_random_uuid(),
        scenario_id uuid NOT NULL,
        scenario_version integer NOT NULL,
        locked_config jsonb NOT NULL,
        config_hash public.sha256_hex NOT NULL,
        baseline_policy_id text NOT NULL,
        baseline_policy_version integer NOT NULL,
        target_policy_id text NOT NULL,
        target_policy_version integer NOT NULL,
        eval_config_version public.version_label NOT NULL,
        repetitions integer NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT pk_replay_pair PRIMARY KEY (id),
        CONSTRAINT uq_replay_pair_binding UNIQUE (
            id, config_hash, baseline_policy_id, baseline_policy_version,
            target_policy_id, target_policy_version
        ),
        CONSTRAINT uq_replay_pair_repetitions UNIQUE (id, repetitions),
        CONSTRAINT fk_replay_pair_scenario FOREIGN KEY (scenario_id, scenario_version)
            REFERENCES intel.scenario (scenario_id, version),
        CONSTRAINT fk_replay_pair_baseline_policy
            FOREIGN KEY (baseline_policy_id, baseline_policy_version)
            REFERENCES security.policy (policy_id, version),
        CONSTRAINT fk_replay_pair_target_policy
            FOREIGN KEY (target_policy_id, target_policy_version)
            REFERENCES security.policy (policy_id, version),
        CONSTRAINT fk_replay_pair_eval_config
            FOREIGN KEY (eval_config_version) REFERENCES eval.eval_config (version),
        CONSTRAINT ck_replay_pair_repetitions CHECK (repetitions BETWEEN 1 AND 10)
    );

    CREATE TABLE eval.replay_run (
        id uuid NOT NULL DEFAULT gen_random_uuid(),
        pair_id uuid NOT NULL,
        repetition_index integer NOT NULL,
        run_role public.run_role NOT NULL,
        order_in_repetition smallint NOT NULL,
        execution_id uuid NOT NULL,
        config_hash public.sha256_hex NOT NULL,
        baseline_policy_id text NOT NULL,
        baseline_policy_version integer NOT NULL,
        target_policy_id text NOT NULL,
        target_policy_version integer NOT NULL,
        enforced_policy_id text NOT NULL,
        enforced_policy_version integer NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT pk_replay_run PRIMARY KEY (id),
        CONSTRAINT uq_replay_run_execution UNIQUE (execution_id),
        CONSTRAINT uq_replay_run_arm UNIQUE (pair_id, repetition_index, run_role),
        CONSTRAINT uq_replay_run_order UNIQUE (pair_id, repetition_index, order_in_repetition),
        CONSTRAINT fk_replay_run_pair FOREIGN KEY (
            pair_id, config_hash, baseline_policy_id, baseline_policy_version,
            target_policy_id, target_policy_version
        ) REFERENCES eval.replay_pair (
            id, config_hash, baseline_policy_id, baseline_policy_version,
            target_policy_id, target_policy_version
        ),
        CONSTRAINT fk_replay_run_execution FOREIGN KEY (
            execution_id, run_role, config_hash, enforced_policy_id, enforced_policy_version,
            target_policy_id, target_policy_version
        ) REFERENCES agent.execution (
            id, run_role, config_hash, enforced_policy_id, enforced_policy_version,
            target_policy_id, target_policy_version
        ),
        CONSTRAINT ck_replay_run_role CHECK (run_role IN ('baseline', 'protected')),
        CONSTRAINT ck_replay_run_repetition CHECK (repetition_index BETWEEN 0 AND 9),
        CONSTRAINT ck_replay_run_order CHECK (order_in_repetition IN (0, 1)),
        CONSTRAINT ck_replay_run_enforced_policy CHECK (
            (run_role = 'baseline'
                AND enforced_policy_id = baseline_policy_id
                AND enforced_policy_version = baseline_policy_version)
            OR (run_role = 'protected'
                AND enforced_policy_id = target_policy_id
                AND enforced_policy_version = target_policy_version)
        )
    );

    CREATE TABLE eval.blast_radius (
        execution_id uuid NOT NULL,
        eval_config_version public.version_label NOT NULL,
        u_attempted integer NOT NULL,
        u_allowed integer NOT NULL,
        r_public integer NOT NULL,
        r_private integer NOT NULL,
        r_sensitive integer NOT NULL,
        x_attempted smallint NOT NULL,
        x_succeeded smallint NOT NULL,
        v integer NOT NULL,
        tool_calls integer NOT NULL,
        legit_calls integer NOT NULL,
        false_blocks integer NOT NULL,
        score integer NOT NULL,
        label public.br_label NOT NULL,
        attack_attempted boolean NOT NULL,
        attack_succeeded boolean NOT NULL,
        task_succeeded boolean NOT NULL,
        had_enforced_deny boolean NOT NULL,
        computed_at timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT pk_blast_radius PRIMARY KEY (execution_id),
        CONSTRAINT fk_blast_radius_execution FOREIGN KEY (execution_id, eval_config_version)
            REFERENCES agent.execution (id, eval_config_version),
        CONSTRAINT fk_blast_radius_eval_config
            FOREIGN KEY (eval_config_version) REFERENCES eval.eval_config (version),
        CONSTRAINT ck_blast_radius_non_negative CHECK (
            u_attempted >= 0 AND u_allowed >= 0 AND r_public >= 0 AND r_private >= 0
            AND r_sensitive >= 0 AND v >= 0 AND tool_calls >= 0 AND legit_calls >= 0
            AND false_blocks >= 0 AND score >= 0
        ),
        CONSTRAINT ck_blast_radius_exfiltration CHECK (
            x_attempted IN (0, 1) AND x_succeeded IN (0, 1) AND x_succeeded <= x_attempted
        ),
        -- Definitions (FR-029, FR-034a): allowed/blocked are subsets of attempts.
        CONSTRAINT ck_blast_radius_subsets CHECK (
            u_allowed <= u_attempted AND u_attempted <= tool_calls
            AND legit_calls <= tool_calls AND false_blocks <= legit_calls
        )
    );

    CREATE TABLE eval.evaluation_result (
        pair_id uuid NOT NULL,
        validity public.pair_validity NOT NULL,
        drift_details jsonb,
        n_requested integer NOT NULL,
        n_valid integer NOT NULL,
        n_excluded integer NOT NULL,
        baseline_metrics jsonb,
        protected_metrics jsonb,
        deltas jsonb,
        single_observation boolean NOT NULL,
        limitation_disclosure text NOT NULL,
        computed_at timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT pk_evaluation_result PRIMARY KEY (pair_id),
        CONSTRAINT fk_evaluation_result_pair FOREIGN KEY (pair_id, n_requested)
            REFERENCES eval.replay_pair (id, repetitions),
        CONSTRAINT ck_evaluation_result_counts CHECK (
            n_valid >= 0 AND n_excluded >= 0 AND n_valid + n_excluded = n_requested
        ),
        CONSTRAINT ck_evaluation_result_drift
            CHECK ((validity = 'invalid_drift') = (drift_details IS NOT NULL)),
        CONSTRAINT ck_evaluation_result_single_observation
            CHECK (single_observation = (n_valid = 1))
    );
    """)


def downgrade() -> None:
    op.execute("""
    DROP TABLE eval.evaluation_result;
    DROP TABLE eval.blast_radius;
    DROP TABLE eval.replay_run;
    DROP TABLE eval.replay_pair;
    """)
