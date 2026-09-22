"""Security telemetry (PRD FR-018, FR-022, FR-025–FR-027, FR-029, FR-044, FR-046).

Every step row carries (execution_id, seq), unique per table, so the trajectory
seal can verify a gap-free ordering (ARCHITECTURE.md §19). Child rows reference
their tool invocation through (tool_invocation_id, execution_id), so no step
can be attached to another execution's invocation. A policy decision must name
exactly its execution's enforced and target policies and the loaded content
hash of each (FR-022). All tables here are append-only (0012).

Revision ID: 0009
Revises: 0008
"""

from __future__ import annotations

from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE security.tool_invocation (
        id uuid NOT NULL DEFAULT gen_random_uuid(),
        execution_id uuid NOT NULL,
        seq integer NOT NULL,
        received_at timestamptz NOT NULL,
        tool text NOT NULL,
        endpoint text,
        canonical_args jsonb,
        raw_args_sha256 public.sha256_hex NOT NULL,
        validation_status public.validation_status NOT NULL,
        rejection_reason text,
        resource_asset_id text,
        resource_tier public.tier,
        destination_trust public.destination_trust,
        CONSTRAINT pk_tool_invocation PRIMARY KEY (id),
        CONSTRAINT uq_tool_invocation_execution_seq UNIQUE (execution_id, seq),
        CONSTRAINT uq_tool_invocation_id_execution UNIQUE (id, execution_id),
        CONSTRAINT fk_tool_invocation_execution
            FOREIGN KEY (execution_id) REFERENCES agent.execution (id),
        CONSTRAINT ck_tool_invocation_seq CHECK (seq >= 1),
        CONSTRAINT ck_tool_invocation_tool CHECK (char_length(tool) <= 64),
        CONSTRAINT ck_tool_invocation_endpoint CHECK (char_length(endpoint) <= 64),
        CONSTRAINT ck_tool_invocation_validation CHECK (
            (validation_status = 'valid' AND canonical_args IS NOT NULL
                AND rejection_reason IS NULL)
            OR (validation_status = 'rejected' AND canonical_args IS NULL
                AND rejection_reason IS NOT NULL)
        )
    );

    CREATE TABLE security.policy_decision (
        id uuid NOT NULL DEFAULT gen_random_uuid(),
        execution_id uuid NOT NULL,
        seq integer NOT NULL,
        tool_invocation_id uuid NOT NULL,
        enforced_policy_id text NOT NULL,
        enforced_policy_version integer NOT NULL,
        enforced_content_sha256 public.sha256_hex NOT NULL,
        enforced_permission public.decision,
        enforced_dataflow public.decision,
        enforced_final public.decision NOT NULL,
        enforced_matched_rules text[] NOT NULL DEFAULT '{}',
        target_policy_id text NOT NULL,
        target_policy_version integer NOT NULL,
        target_content_sha256 public.sha256_hex NOT NULL,
        target_permission public.decision,
        target_dataflow public.decision,
        target_final public.decision NOT NULL,
        target_matched_rules text[] NOT NULL DEFAULT '{}',
        reason_code public.reason_code NOT NULL,
        taint_snapshot_sha256 public.sha256_hex NOT NULL,
        approval_resolution public.approval_resolution,
        decided_at timestamptz NOT NULL,
        decision_latency_ms numeric(10, 3) NOT NULL,
        CONSTRAINT pk_policy_decision PRIMARY KEY (id),
        CONSTRAINT uq_policy_decision_execution_seq UNIQUE (execution_id, seq),
        CONSTRAINT uq_policy_decision_tool_invocation UNIQUE (tool_invocation_id),
        CONSTRAINT fk_policy_decision_tool_invocation FOREIGN KEY (tool_invocation_id, execution_id)
            REFERENCES security.tool_invocation (id, execution_id),
        CONSTRAINT fk_policy_decision_execution_policies FOREIGN KEY (
            execution_id, enforced_policy_id, enforced_policy_version,
            target_policy_id, target_policy_version
        ) REFERENCES agent.execution (
            id, enforced_policy_id, enforced_policy_version,
            target_policy_id, target_policy_version
        ),
        CONSTRAINT fk_policy_decision_enforced_content
            FOREIGN KEY (enforced_policy_id, enforced_policy_version, enforced_content_sha256)
            REFERENCES security.policy (policy_id, version, content_sha256),
        CONSTRAINT fk_policy_decision_target_content
            FOREIGN KEY (target_policy_id, target_policy_version, target_content_sha256)
            REFERENCES security.policy (policy_id, version, content_sha256),
        CONSTRAINT ck_policy_decision_seq CHECK (seq >= 1),
        -- The Policy Engine was consulted unless the request never reached it.
        CONSTRAINT ck_policy_decision_components CHECK (
            reason_code IN ('validation_error', 'system_error', 'step_limit')
            OR (enforced_permission IS NOT NULL AND enforced_dataflow IS NOT NULL
                AND target_permission IS NOT NULL AND target_dataflow IS NOT NULL)
        ),
        -- Requests that never reached the Policy Engine are denied (NFR-006).
        CONSTRAINT ck_policy_decision_fail_closed CHECK (
            reason_code NOT IN ('validation_error', 'system_error', 'step_limit')
            OR enforced_final = 'DENY'
        ),
        CONSTRAINT ck_policy_decision_approval
            CHECK (approval_resolution IS NULL OR enforced_final = 'APPROVAL'),
        CONSTRAINT ck_policy_decision_latency CHECK (decision_latency_ms >= 0)
    );

    CREATE TABLE security.tool_result (
        id uuid NOT NULL DEFAULT gen_random_uuid(),
        execution_id uuid NOT NULL,
        seq integer NOT NULL,
        tool_invocation_id uuid NOT NULL,
        dispatched boolean NOT NULL,
        result jsonb,
        result_sha256 public.sha256_hex,
        returned_asset_ids text[] NOT NULL DEFAULT '{}',
        completed_at timestamptz NOT NULL,
        CONSTRAINT pk_tool_result PRIMARY KEY (id),
        CONSTRAINT uq_tool_result_execution_seq UNIQUE (execution_id, seq),
        CONSTRAINT uq_tool_result_tool_invocation UNIQUE (tool_invocation_id),
        CONSTRAINT fk_tool_result_tool_invocation FOREIGN KEY (tool_invocation_id, execution_id)
            REFERENCES security.tool_invocation (id, execution_id),
        CONSTRAINT ck_tool_result_seq CHECK (seq >= 1),
        -- A request that was not dispatched returned nothing.
        CONSTRAINT ck_tool_result_not_dispatched CHECK (
            dispatched OR (result IS NULL AND result_sha256 IS NULL
                AND cardinality(returned_asset_ids) = 0)
        )
    );

    CREATE TABLE security.data_flow_event (
        id uuid NOT NULL DEFAULT gen_random_uuid(),
        execution_id uuid NOT NULL,
        seq integer NOT NULL,
        tool_invocation_id uuid NOT NULL,
        kind public.flow_kind NOT NULL,
        asset_id text NOT NULL,
        source_tier public.tier NOT NULL,
        marker_kind public.marker_kind NOT NULL,
        destination_trust public.destination_trust,
        dataflow_rule_result public.decision,
        CONSTRAINT pk_data_flow_event PRIMARY KEY (id),
        CONSTRAINT uq_data_flow_event_execution_seq UNIQUE (execution_id, seq),
        CONSTRAINT fk_data_flow_event_tool_invocation FOREIGN KEY (tool_invocation_id, execution_id)
            REFERENCES security.tool_invocation (id, execution_id),
        CONSTRAINT ck_data_flow_event_seq CHECK (seq >= 1),
        -- Only private/sensitive assets carry taint markers (FR-024).
        CONSTRAINT ck_data_flow_event_tier CHECK (source_tier <> 'public'),
        CONSTRAINT ck_data_flow_event_sink CHECK (
            (kind = 'sink_match')
            = (destination_trust IS NOT NULL AND dataflow_rule_result IS NOT NULL)
        )
    );
    CREATE INDEX ix_data_flow_event_execution_kind ON security.data_flow_event (execution_id, kind);

    CREATE TABLE security.security_violation (
        id uuid NOT NULL DEFAULT gen_random_uuid(),
        execution_id uuid NOT NULL,
        seq integer NOT NULL,
        tool_invocation_id uuid NOT NULL,
        target_decision public.decision NOT NULL,
        enforced_decision public.decision NOT NULL,
        blocked boolean NOT NULL,
        CONSTRAINT pk_security_violation PRIMARY KEY (id),
        CONSTRAINT uq_security_violation_execution_seq UNIQUE (execution_id, seq),
        CONSTRAINT uq_security_violation_tool_invocation UNIQUE (tool_invocation_id),
        CONSTRAINT fk_security_violation_tool_invocation
            FOREIGN KEY (tool_invocation_id, execution_id)
            REFERENCES security.tool_invocation (id, execution_id),
        CONSTRAINT ck_security_violation_seq CHECK (seq >= 1),
        CONSTRAINT ck_security_violation_target CHECK (target_decision <> 'ALLOW'),
        CONSTRAINT ck_security_violation_blocked CHECK (blocked = (enforced_decision <> 'ALLOW'))
    );

    CREATE TABLE security.system_failure_event (
        id uuid NOT NULL DEFAULT gen_random_uuid(),
        execution_id uuid,
        seq integer,
        component text NOT NULL,
        failure_class public.failure_class NOT NULL,
        detail text NOT NULL,
        occurred_at timestamptz NOT NULL,
        CONSTRAINT pk_system_failure_event PRIMARY KEY (id),
        CONSTRAINT uq_system_failure_event_execution_seq UNIQUE (execution_id, seq),
        CONSTRAINT fk_system_failure_event_execution
            FOREIGN KEY (execution_id) REFERENCES agent.execution (id),
        CONSTRAINT ck_system_failure_event_seq
            CHECK (seq IS NULL OR (execution_id IS NOT NULL AND seq >= 1))
    );
    CREATE INDEX ix_system_failure_event_execution_id
        ON security.system_failure_event (execution_id);

    CREATE TABLE security.model_call (
        id uuid NOT NULL DEFAULT gen_random_uuid(),
        execution_id uuid NOT NULL,
        seq integer NOT NULL,
        requested_model text NOT NULL,
        served_model text,
        request jsonb NOT NULL,
        response jsonb,
        request_sha256 public.sha256_hex NOT NULL,
        response_sha256 public.sha256_hex,
        status public.model_call_status NOT NULL,
        input_tokens integer,
        output_tokens integer,
        started_at timestamptz NOT NULL,
        ended_at timestamptz,
        CONSTRAINT pk_model_call PRIMARY KEY (id),
        CONSTRAINT uq_model_call_execution_seq UNIQUE (execution_id, seq),
        CONSTRAINT fk_model_call_execution
            FOREIGN KEY (execution_id) REFERENCES agent.execution (id),
        CONSTRAINT ck_model_call_seq CHECK (seq >= 1),
        CONSTRAINT ck_model_call_ok CHECK (
            status <> 'ok' OR (response IS NOT NULL AND response_sha256 IS NOT NULL
                AND served_model IS NOT NULL)
        ),
        CONSTRAINT ck_model_call_tokens CHECK (input_tokens >= 0 AND output_tokens >= 0)
    );

    CREATE TABLE security.agent_final_response (
        id uuid NOT NULL DEFAULT gen_random_uuid(),
        execution_id uuid NOT NULL,
        seq integer NOT NULL,
        text public.untrusted_text NOT NULL,
        normalized_text public.untrusted_text NOT NULL,
        received_at timestamptz NOT NULL,
        CONSTRAINT pk_agent_final_response PRIMARY KEY (id),
        CONSTRAINT uq_agent_final_response_execution UNIQUE (execution_id),
        CONSTRAINT uq_agent_final_response_execution_seq UNIQUE (execution_id, seq),
        CONSTRAINT fk_agent_final_response_execution
            FOREIGN KEY (execution_id) REFERENCES agent.execution (id),
        CONSTRAINT ck_agent_final_response_seq CHECK (seq >= 1),
        CONSTRAINT ck_agent_final_response_text CHECK (octet_length(text) <= 16384),
        CONSTRAINT ck_agent_final_response_normalized_text
            CHECK (octet_length(normalized_text) <= 16384)
    );

    CREATE TABLE security.trajectory (
        execution_id uuid NOT NULL,
        step_count integer NOT NULL,
        steps_sha256 public.sha256_hex NOT NULL,
        sealed_at timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT pk_trajectory PRIMARY KEY (execution_id),
        CONSTRAINT fk_trajectory_execution
            FOREIGN KEY (execution_id) REFERENCES agent.execution (id),
        CONSTRAINT ck_trajectory_step_count CHECK (step_count >= 0)
    );
    """)


def downgrade() -> None:
    op.execute("""
    DROP TABLE security.trajectory;
    DROP TABLE security.agent_final_response;
    DROP TABLE security.model_call;
    DROP TABLE security.system_failure_event;
    DROP TABLE security.security_violation;
    DROP TABLE security.data_flow_event;
    DROP TABLE security.tool_result;
    DROP TABLE security.policy_decision;
    DROP TABLE security.tool_invocation;
    """)
