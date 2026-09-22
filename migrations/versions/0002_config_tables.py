"""Versioned configuration tables (ARCHITECTURE.md §24; engineering plan §5.9).

agent.agent_config, agent.agent_task, agent.tool, agent.data_asset,
security.policy, eval.eval_config. Each row is keyed by version and carries a
content hash; rows are insert-only (enforced in 0012).

Revision ID: 0002
Revises: 0001
"""

from __future__ import annotations

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE agent.agent_config (
        agent_id text NOT NULL,
        version integer NOT NULL,
        agent_kind public.agent_kind NOT NULL,
        role text NOT NULL,
        provider text,
        model_id text,
        temperature numeric(4, 3) NOT NULL,
        max_tokens integer NOT NULL,
        system_prompt text NOT NULL,
        system_prompt_sha256 public.sha256_hex NOT NULL,
        tool_definitions_version public.version_label NOT NULL,
        tool_schema_sha256 public.sha256_hex NOT NULL,
        agent_loop_version public.version_label NOT NULL,
        max_steps integer NOT NULL,
        model_call_budget integer NOT NULL,
        timeout_seconds integer NOT NULL,
        scripted_plans jsonb,
        content_sha256 public.sha256_hex NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT pk_agent_config PRIMARY KEY (agent_id, version),
        CONSTRAINT uq_agent_config_tool_definitions
            UNIQUE (agent_id, version, tool_definitions_version),
        CONSTRAINT ck_agent_config_version_positive CHECK (version >= 1),
        CONSTRAINT ck_agent_config_scripted_plans
            CHECK ((agent_kind = 'scripted') = (scripted_plans IS NOT NULL)),
        CONSTRAINT ck_agent_config_llm_model
            CHECK (agent_kind <> 'llm' OR (provider IS NOT NULL AND model_id IS NOT NULL)),
        CONSTRAINT ck_agent_config_limits CHECK (
            temperature >= 0 AND max_tokens > 0 AND max_steps > 0
            AND model_call_budget > 0 AND timeout_seconds > 0
        )
    );

    CREATE TABLE agent.agent_task (
        task_id text NOT NULL,
        version integer NOT NULL,
        prompt text NOT NULL,
        task_document_path text NOT NULL,
        task_fact_tokens text[] NOT NULL,
        content_sha256 public.sha256_hex NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT pk_agent_task PRIMARY KEY (task_id, version),
        CONSTRAINT ck_agent_task_version_positive CHECK (version >= 1),
        CONSTRAINT ck_agent_task_fact_tokens CHECK (cardinality(task_fact_tokens) >= 1)
    );

    CREATE TABLE agent.tool (
        tool_definitions_version public.version_label NOT NULL,
        tool_name public.tool_name NOT NULL,
        endpoint text NOT NULL DEFAULT '',
        destination_trust public.destination_trust NOT NULL,
        argument_schema jsonb NOT NULL,
        content_sha256 public.sha256_hex NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT pk_tool PRIMARY KEY (tool_definitions_version, tool_name, endpoint),
        -- FR-002: only mock_api has endpoints, and only the enumerated ones.
        CONSTRAINT ck_tool_endpoint CHECK (
            (tool_name = 'mock_api' AND endpoint IN ('directory_lookup', 'send_message'))
            OR (tool_name <> 'mock_api' AND endpoint = '')
        )
    );

    CREATE TABLE agent.data_asset (
        fixture_set_version public.version_label NOT NULL,
        asset_id text NOT NULL,
        kind public.asset_kind NOT NULL,
        locator text NOT NULL,
        tier public.tier NOT NULL,
        has_markers boolean NOT NULL,
        content_sha256 public.sha256_hex NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT pk_data_asset PRIMARY KEY (fixture_set_version, asset_id),
        CONSTRAINT uq_data_asset_locator UNIQUE (fixture_set_version, kind, locator),
        -- FR-024: every private/sensitive asset carries taint markers.
        CONSTRAINT ck_data_asset_markers CHECK (tier = 'public' OR has_markers)
    );

    CREATE TABLE security.policy (
        policy_id text NOT NULL,
        version integer NOT NULL,
        content_sha256 public.sha256_hex NOT NULL,
        document jsonb NOT NULL,
        loaded_at timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT pk_policy PRIMARY KEY (policy_id, version),
        CONSTRAINT uq_policy_content UNIQUE (policy_id, version, content_sha256),
        CONSTRAINT ck_policy_version_positive CHECK (version >= 1)
    );

    CREATE TABLE eval.eval_config (
        version public.version_label NOT NULL,
        weights jsonb NOT NULL,
        thresholds jsonb NOT NULL,
        content_sha256 public.sha256_hex NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT pk_eval_config PRIMARY KEY (version)
    );
    """)


def downgrade() -> None:
    op.execute("""
    DROP TABLE eval.eval_config;
    DROP TABLE security.policy;
    DROP TABLE agent.data_asset;
    DROP TABLE agent.tool;
    DROP TABLE agent.agent_task;
    DROP TABLE agent.agent_config;
    """)
