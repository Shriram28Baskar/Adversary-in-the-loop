"""agent schema: versioned configuration and executions (migrations 0002, 0008)."""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any, ClassVar

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKeyConstraint,
    Index,
    Integer,
    Numeric,
    PrimaryKeyConstraint,
    Text,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from aitl_common.db.models.base import Base
from aitl_common.db.types import SHA256_HEX, VERSION_LABEL, domain_column, pg_enum

# agent.execution columns agent-runtime may update (column-level grant, 0012).
EXECUTION_MUTABLE_COLUMNS: tuple[str, ...] = (
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


class AgentConfig(Base):
    __tablename__ = "agent_config"
    __table_args__ = (
        PrimaryKeyConstraint("agent_id", "version", name="pk_agent_config"),
        UniqueConstraint(
            "agent_id",
            "version",
            "tool_definitions_version",
            name="uq_agent_config_tool_definitions",
        ),
        {"schema": "agent"},
    )

    agent_id: Mapped[str] = mapped_column(Text)
    version: Mapped[int] = mapped_column(Integer)
    agent_kind: Mapped[str] = mapped_column(pg_enum("agent_kind"), nullable=False)
    role: Mapped[str] = mapped_column(Text, nullable=False)
    provider: Mapped[str | None] = mapped_column(Text, nullable=True)
    model_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    temperature: Mapped[Decimal] = mapped_column(Numeric(4, 3), nullable=False)
    max_tokens: Mapped[int] = mapped_column(Integer, nullable=False)
    system_prompt: Mapped[str] = mapped_column(Text, nullable=False)
    system_prompt_sha256: Mapped[str] = domain_column(SHA256_HEX)
    tool_definitions_version: Mapped[str] = domain_column(VERSION_LABEL)
    tool_schema_sha256: Mapped[str] = domain_column(SHA256_HEX)
    agent_loop_version: Mapped[str] = domain_column(VERSION_LABEL)
    max_steps: Mapped[int] = mapped_column(Integer, nullable=False)
    model_call_budget: Mapped[int] = mapped_column(Integer, nullable=False)
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    scripted_plans: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    content_sha256: Mapped[str] = domain_column(SHA256_HEX)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class AgentTask(Base):
    __tablename__ = "agent_task"
    __table_args__ = (
        PrimaryKeyConstraint("task_id", "version", name="pk_agent_task"),
        {"schema": "agent"},
    )

    task_id: Mapped[str] = mapped_column(Text)
    version: Mapped[int] = mapped_column(Integer)
    prompt: Mapped[str] = mapped_column(Text, nullable=False)
    task_document_path: Mapped[str] = mapped_column(Text, nullable=False)
    task_fact_tokens: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False)
    content_sha256: Mapped[str] = domain_column(SHA256_HEX)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class Tool(Base):
    __tablename__ = "tool"
    __table_args__ = (
        PrimaryKeyConstraint("tool_definitions_version", "tool_name", "endpoint", name="pk_tool"),
        {"schema": "agent"},
    )

    tool_definitions_version: Mapped[str] = domain_column(VERSION_LABEL)
    tool_name: Mapped[str] = mapped_column(pg_enum("tool_name"))
    endpoint: Mapped[str] = mapped_column(Text, server_default="")
    destination_trust: Mapped[str] = mapped_column(pg_enum("destination_trust"), nullable=False)
    argument_schema: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    content_sha256: Mapped[str] = domain_column(SHA256_HEX)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class DataAsset(Base):
    __tablename__ = "data_asset"
    __table_args__ = (
        PrimaryKeyConstraint("fixture_set_version", "asset_id", name="pk_data_asset"),
        UniqueConstraint("fixture_set_version", "kind", "locator", name="uq_data_asset_locator"),
        {"schema": "agent"},
    )

    fixture_set_version: Mapped[str] = domain_column(VERSION_LABEL)
    asset_id: Mapped[str] = mapped_column(Text)
    kind: Mapped[str] = mapped_column(pg_enum("asset_kind"), nullable=False)
    locator: Mapped[str] = mapped_column(Text, nullable=False)
    tier: Mapped[str] = mapped_column(pg_enum("tier"), nullable=False)
    has_markers: Mapped[bool] = mapped_column(Boolean, nullable=False)
    content_sha256: Mapped[str] = domain_column(SHA256_HEX)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class Execution(Base):
    """One run of one scenario version under one locked configuration.

    Only ``EXECUTION_MUTABLE_COLUMNS`` may change, and only forward through the
    lifecycle; the database enforces both (trigger + column grants).
    """

    APPEND_ONLY: ClassVar[bool] = False
    __tablename__ = "execution"
    __table_args__ = (
        PrimaryKeyConstraint("id", name="pk_execution"),
        ForeignKeyConstraint(
            ["scenario_id", "scenario_version", "fixture_set_version"],
            [
                "intel.scenario.scenario_id",
                "intel.scenario.version",
                "intel.scenario.fixture_set_version",
            ],
            name="fk_execution_scenario",
        ),
        ForeignKeyConstraint(
            ["agent_id", "agent_version", "tool_definitions_version"],
            [
                "agent.agent_config.agent_id",
                "agent.agent_config.version",
                "agent.agent_config.tool_definitions_version",
            ],
            name="fk_execution_agent_config",
        ),
        ForeignKeyConstraint(
            ["eval_config_version"], ["eval.eval_config.version"], name="fk_execution_eval_config"
        ),
        ForeignKeyConstraint(
            ["enforced_policy_id", "enforced_policy_version"],
            ["security.policy.policy_id", "security.policy.version"],
            name="fk_execution_enforced_policy",
        ),
        ForeignKeyConstraint(
            ["target_policy_id", "target_policy_version"],
            ["security.policy.policy_id", "security.policy.version"],
            name="fk_execution_target_policy",
        ),
        UniqueConstraint(
            "id",
            "enforced_policy_id",
            "enforced_policy_version",
            "target_policy_id",
            "target_policy_version",
            name="uq_execution_policies",
        ),
        UniqueConstraint(
            "id",
            "run_role",
            "config_hash",
            "enforced_policy_id",
            "enforced_policy_version",
            "target_policy_id",
            "target_policy_version",
            name="uq_execution_replay_binding",
        ),
        UniqueConstraint("id", "eval_config_version", name="uq_execution_eval_config"),
        Index("ix_execution_lifecycle_queued_at", "lifecycle", "queued_at"),
        Index("ix_execution_scenario", "scenario_id", "scenario_version"),
        {"schema": "agent"},
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, server_default=func.gen_random_uuid())
    scenario_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    scenario_version: Mapped[int] = mapped_column(Integer, nullable=False)
    agent_id: Mapped[str] = mapped_column(Text, nullable=False)
    agent_version: Mapped[int] = mapped_column(Integer, nullable=False)
    fixture_set_version: Mapped[str] = domain_column(VERSION_LABEL)
    tool_definitions_version: Mapped[str] = domain_column(VERSION_LABEL)
    sandbox_seed: Mapped[int] = mapped_column(BigInteger, nullable=False)
    eval_config_version: Mapped[str] = domain_column(VERSION_LABEL)
    enforced_policy_id: Mapped[str] = mapped_column(Text, nullable=False)
    enforced_policy_version: Mapped[int] = mapped_column(Integer, nullable=False)
    target_policy_id: Mapped[str] = mapped_column(Text, nullable=False)
    target_policy_version: Mapped[int] = mapped_column(Integer, nullable=False)
    run_role: Mapped[str] = mapped_column(pg_enum("run_role"), nullable=False)
    locked_config: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    config_hash: Mapped[str] = domain_column(SHA256_HEX)
    lifecycle: Mapped[str] = mapped_column(
        pg_enum("lifecycle"), nullable=False, server_default="pending"
    )
    error_class: Mapped[str | None] = mapped_column(pg_enum("error_class"), nullable=True)
    termination_reason: Mapped[str | None] = mapped_column(
        pg_enum("termination_reason"), nullable=True
    )
    teardown_verified: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    token_hash: Mapped[str | None] = domain_column(SHA256_HEX, nullable=True)
    sandbox_image_digest_as_run: Mapped[str | None] = mapped_column(Text, nullable=True)
    gateway_build_as_run: Mapped[str | None] = mapped_column(Text, nullable=True)
    fixture_checksum_as_run: Mapped[str | None] = domain_column(SHA256_HEX, nullable=True)
    queued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
