"""security schema: policies and append-only security telemetry (migrations 0002, 0009)."""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
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
from aitl_common.db.types import SHA256_HEX, UNTRUSTED_TEXT, domain_column, pg_enum


def _step_constraints(table: str) -> tuple[Any, ...]:
    """(execution_id, seq) is unique per step table (trajectory ordering, §19)."""
    return (
        PrimaryKeyConstraint("id", name=f"pk_{table}"),
        UniqueConstraint("execution_id", "seq", name=f"uq_{table}_execution_seq"),
    )


def _invocation_fk(table: str) -> ForeignKeyConstraint:
    return ForeignKeyConstraint(
        ["tool_invocation_id", "execution_id"],
        ["security.tool_invocation.id", "security.tool_invocation.execution_id"],
        name=f"fk_{table}_tool_invocation",
    )


class Policy(Base):
    __tablename__ = "policy"
    __table_args__ = (
        PrimaryKeyConstraint("policy_id", "version", name="pk_policy"),
        UniqueConstraint("policy_id", "version", "content_sha256", name="uq_policy_content"),
        {"schema": "security"},
    )

    policy_id: Mapped[str] = mapped_column(Text)
    version: Mapped[int] = mapped_column(Integer)
    content_sha256: Mapped[str] = domain_column(SHA256_HEX)
    document: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    loaded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class ToolInvocation(Base):
    __tablename__ = "tool_invocation"
    __table_args__ = (
        *_step_constraints("tool_invocation"),
        UniqueConstraint("id", "execution_id", name="uq_tool_invocation_id_execution"),
        ForeignKeyConstraint(
            ["execution_id"], ["agent.execution.id"], name="fk_tool_invocation_execution"
        ),
        {"schema": "security"},
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, server_default=func.gen_random_uuid())
    execution_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    tool: Mapped[str] = mapped_column(Text, nullable=False)
    endpoint: Mapped[str | None] = mapped_column(Text, nullable=True)
    canonical_args: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    raw_args_sha256: Mapped[str] = domain_column(SHA256_HEX)
    validation_status: Mapped[str] = mapped_column(pg_enum("validation_status"), nullable=False)
    rejection_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    resource_asset_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    resource_tier: Mapped[str | None] = mapped_column(pg_enum("tier"), nullable=True)
    destination_trust: Mapped[str | None] = mapped_column(
        pg_enum("destination_trust"), nullable=True
    )


class PolicyDecision(Base):
    __tablename__ = "policy_decision"
    __table_args__ = (
        *_step_constraints("policy_decision"),
        UniqueConstraint("tool_invocation_id", name="uq_policy_decision_tool_invocation"),
        _invocation_fk("policy_decision"),
        ForeignKeyConstraint(
            [
                "execution_id",
                "enforced_policy_id",
                "enforced_policy_version",
                "target_policy_id",
                "target_policy_version",
            ],
            [
                "agent.execution.id",
                "agent.execution.enforced_policy_id",
                "agent.execution.enforced_policy_version",
                "agent.execution.target_policy_id",
                "agent.execution.target_policy_version",
            ],
            name="fk_policy_decision_execution_policies",
        ),
        ForeignKeyConstraint(
            ["enforced_policy_id", "enforced_policy_version", "enforced_content_sha256"],
            [
                "security.policy.policy_id",
                "security.policy.version",
                "security.policy.content_sha256",
            ],
            name="fk_policy_decision_enforced_content",
        ),
        ForeignKeyConstraint(
            ["target_policy_id", "target_policy_version", "target_content_sha256"],
            [
                "security.policy.policy_id",
                "security.policy.version",
                "security.policy.content_sha256",
            ],
            name="fk_policy_decision_target_content",
        ),
        {"schema": "security"},
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, server_default=func.gen_random_uuid())
    execution_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    tool_invocation_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    enforced_policy_id: Mapped[str] = mapped_column(Text, nullable=False)
    enforced_policy_version: Mapped[int] = mapped_column(Integer, nullable=False)
    enforced_content_sha256: Mapped[str] = domain_column(SHA256_HEX)
    enforced_permission: Mapped[str | None] = mapped_column(pg_enum("decision"), nullable=True)
    enforced_dataflow: Mapped[str | None] = mapped_column(pg_enum("decision"), nullable=True)
    enforced_final: Mapped[str] = mapped_column(pg_enum("decision"), nullable=False)
    enforced_matched_rules: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, server_default="{}"
    )
    target_policy_id: Mapped[str] = mapped_column(Text, nullable=False)
    target_policy_version: Mapped[int] = mapped_column(Integer, nullable=False)
    target_content_sha256: Mapped[str] = domain_column(SHA256_HEX)
    target_permission: Mapped[str | None] = mapped_column(pg_enum("decision"), nullable=True)
    target_dataflow: Mapped[str | None] = mapped_column(pg_enum("decision"), nullable=True)
    target_final: Mapped[str] = mapped_column(pg_enum("decision"), nullable=False)
    target_matched_rules: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, server_default="{}"
    )
    reason_code: Mapped[str] = mapped_column(pg_enum("reason_code"), nullable=False)
    taint_snapshot_sha256: Mapped[str] = domain_column(SHA256_HEX)
    approval_resolution: Mapped[str | None] = mapped_column(
        pg_enum("approval_resolution"), nullable=True
    )
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    decision_latency_ms: Mapped[Decimal] = mapped_column(Numeric(10, 3), nullable=False)


class ToolResult(Base):
    __tablename__ = "tool_result"
    __table_args__ = (
        *_step_constraints("tool_result"),
        UniqueConstraint("tool_invocation_id", name="uq_tool_result_tool_invocation"),
        _invocation_fk("tool_result"),
        {"schema": "security"},
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, server_default=func.gen_random_uuid())
    execution_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    tool_invocation_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    dispatched: Mapped[bool] = mapped_column(Boolean, nullable=False)
    result: Mapped[Any] = mapped_column(JSONB, nullable=True)
    result_sha256: Mapped[str | None] = domain_column(SHA256_HEX, nullable=True)
    returned_asset_ids: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, server_default="{}"
    )
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class DataFlowEvent(Base):
    __tablename__ = "data_flow_event"
    __table_args__ = (
        *_step_constraints("data_flow_event"),
        _invocation_fk("data_flow_event"),
        Index("ix_data_flow_event_execution_kind", "execution_id", "kind"),
        {"schema": "security"},
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, server_default=func.gen_random_uuid())
    execution_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    tool_invocation_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    kind: Mapped[str] = mapped_column(pg_enum("flow_kind"), nullable=False)
    asset_id: Mapped[str] = mapped_column(Text, nullable=False)
    source_tier: Mapped[str] = mapped_column(pg_enum("tier"), nullable=False)
    marker_kind: Mapped[str] = mapped_column(pg_enum("marker_kind"), nullable=False)
    destination_trust: Mapped[str | None] = mapped_column(
        pg_enum("destination_trust"), nullable=True
    )
    dataflow_rule_result: Mapped[str | None] = mapped_column(pg_enum("decision"), nullable=True)


class SecurityViolation(Base):
    __tablename__ = "security_violation"
    __table_args__ = (
        *_step_constraints("security_violation"),
        UniqueConstraint("tool_invocation_id", name="uq_security_violation_tool_invocation"),
        _invocation_fk("security_violation"),
        {"schema": "security"},
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, server_default=func.gen_random_uuid())
    execution_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    tool_invocation_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    target_decision: Mapped[str] = mapped_column(pg_enum("decision"), nullable=False)
    enforced_decision: Mapped[str] = mapped_column(pg_enum("decision"), nullable=False)
    blocked: Mapped[bool] = mapped_column(Boolean, nullable=False)


class SystemFailureEvent(Base):
    __tablename__ = "system_failure_event"
    __table_args__ = (
        PrimaryKeyConstraint("id", name="pk_system_failure_event"),
        UniqueConstraint("execution_id", "seq", name="uq_system_failure_event_execution_seq"),
        ForeignKeyConstraint(
            ["execution_id"], ["agent.execution.id"], name="fk_system_failure_event_execution"
        ),
        Index("ix_system_failure_event_execution_id", "execution_id"),
        {"schema": "security"},
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, server_default=func.gen_random_uuid())
    execution_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    seq: Mapped[int | None] = mapped_column(Integer, nullable=True)
    component: Mapped[str] = mapped_column(Text, nullable=False)
    failure_class: Mapped[str] = mapped_column(pg_enum("failure_class"), nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ModelCall(Base):
    __tablename__ = "model_call"
    __table_args__ = (
        *_step_constraints("model_call"),
        ForeignKeyConstraint(
            ["execution_id"], ["agent.execution.id"], name="fk_model_call_execution"
        ),
        {"schema": "security"},
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, server_default=func.gen_random_uuid())
    execution_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    requested_model: Mapped[str] = mapped_column(Text, nullable=False)
    served_model: Mapped[str | None] = mapped_column(Text, nullable=True)
    request: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    response: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    request_sha256: Mapped[str] = domain_column(SHA256_HEX)
    response_sha256: Mapped[str | None] = domain_column(SHA256_HEX, nullable=True)
    status: Mapped[str] = mapped_column(pg_enum("model_call_status"), nullable=False)
    input_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    output_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AgentFinalResponse(Base):
    __tablename__ = "agent_final_response"
    __table_args__ = (
        *_step_constraints("agent_final_response"),
        UniqueConstraint("execution_id", name="uq_agent_final_response_execution"),
        ForeignKeyConstraint(
            ["execution_id"], ["agent.execution.id"], name="fk_agent_final_response_execution"
        ),
        {"schema": "security"},
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, server_default=func.gen_random_uuid())
    execution_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    text: Mapped[str] = domain_column(UNTRUSTED_TEXT)
    normalized_text: Mapped[str] = domain_column(UNTRUSTED_TEXT)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Trajectory(Base):
    __tablename__ = "trajectory"
    __table_args__ = (
        PrimaryKeyConstraint("execution_id", name="pk_trajectory"),
        ForeignKeyConstraint(
            ["execution_id"], ["agent.execution.id"], name="fk_trajectory_execution"
        ),
        {"schema": "security"},
    )

    execution_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    step_count: Mapped[int] = mapped_column(Integer, nullable=False)
    steps_sha256: Mapped[str] = domain_column(SHA256_HEX)
    sealed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
