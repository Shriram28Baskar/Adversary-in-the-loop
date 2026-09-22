"""eval schema: evaluation configuration, replay pairs, results (migrations 0002, 0010)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKeyConstraint,
    Integer,
    PrimaryKeyConstraint,
    SmallInteger,
    Text,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from aitl_common.db.models.base import Base
from aitl_common.db.types import SHA256_HEX, VERSION_LABEL, domain_column, pg_enum


class EvalConfig(Base):
    __tablename__ = "eval_config"
    __table_args__ = (PrimaryKeyConstraint("version", name="pk_eval_config"), {"schema": "eval"})

    version: Mapped[str] = domain_column(VERSION_LABEL)
    weights: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    thresholds: Mapped[Any] = mapped_column(JSONB, nullable=False)
    content_sha256: Mapped[str] = domain_column(SHA256_HEX)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class ReplayPair(Base):
    __tablename__ = "replay_pair"
    __table_args__ = (
        PrimaryKeyConstraint("id", name="pk_replay_pair"),
        UniqueConstraint(
            "id",
            "config_hash",
            "baseline_policy_id",
            "baseline_policy_version",
            "target_policy_id",
            "target_policy_version",
            name="uq_replay_pair_binding",
        ),
        UniqueConstraint("id", "repetitions", name="uq_replay_pair_repetitions"),
        ForeignKeyConstraint(
            ["scenario_id", "scenario_version"],
            ["intel.scenario.scenario_id", "intel.scenario.version"],
            name="fk_replay_pair_scenario",
        ),
        ForeignKeyConstraint(
            ["baseline_policy_id", "baseline_policy_version"],
            ["security.policy.policy_id", "security.policy.version"],
            name="fk_replay_pair_baseline_policy",
        ),
        ForeignKeyConstraint(
            ["target_policy_id", "target_policy_version"],
            ["security.policy.policy_id", "security.policy.version"],
            name="fk_replay_pair_target_policy",
        ),
        ForeignKeyConstraint(
            ["eval_config_version"], ["eval.eval_config.version"], name="fk_replay_pair_eval_config"
        ),
        {"schema": "eval"},
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, server_default=func.gen_random_uuid())
    scenario_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    scenario_version: Mapped[int] = mapped_column(Integer, nullable=False)
    locked_config: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    config_hash: Mapped[str] = domain_column(SHA256_HEX)
    baseline_policy_id: Mapped[str] = mapped_column(Text, nullable=False)
    baseline_policy_version: Mapped[int] = mapped_column(Integer, nullable=False)
    target_policy_id: Mapped[str] = mapped_column(Text, nullable=False)
    target_policy_version: Mapped[int] = mapped_column(Integer, nullable=False)
    eval_config_version: Mapped[str] = domain_column(VERSION_LABEL)
    repetitions: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class ReplayRun(Base):
    """One arm of one repetition; composite keys bind it to its pair and execution (FR-033a)."""

    __tablename__ = "replay_run"
    __table_args__ = (
        PrimaryKeyConstraint("id", name="pk_replay_run"),
        UniqueConstraint("execution_id", name="uq_replay_run_execution"),
        UniqueConstraint("pair_id", "repetition_index", "run_role", name="uq_replay_run_arm"),
        UniqueConstraint(
            "pair_id", "repetition_index", "order_in_repetition", name="uq_replay_run_order"
        ),
        ForeignKeyConstraint(
            [
                "pair_id",
                "config_hash",
                "baseline_policy_id",
                "baseline_policy_version",
                "target_policy_id",
                "target_policy_version",
            ],
            [
                "eval.replay_pair.id",
                "eval.replay_pair.config_hash",
                "eval.replay_pair.baseline_policy_id",
                "eval.replay_pair.baseline_policy_version",
                "eval.replay_pair.target_policy_id",
                "eval.replay_pair.target_policy_version",
            ],
            name="fk_replay_run_pair",
        ),
        ForeignKeyConstraint(
            [
                "execution_id",
                "run_role",
                "config_hash",
                "enforced_policy_id",
                "enforced_policy_version",
                "target_policy_id",
                "target_policy_version",
            ],
            [
                "agent.execution.id",
                "agent.execution.run_role",
                "agent.execution.config_hash",
                "agent.execution.enforced_policy_id",
                "agent.execution.enforced_policy_version",
                "agent.execution.target_policy_id",
                "agent.execution.target_policy_version",
            ],
            name="fk_replay_run_execution",
        ),
        {"schema": "eval"},
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, server_default=func.gen_random_uuid())
    pair_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    repetition_index: Mapped[int] = mapped_column(Integer, nullable=False)
    run_role: Mapped[str] = mapped_column(pg_enum("run_role"), nullable=False)
    order_in_repetition: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    execution_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    config_hash: Mapped[str] = domain_column(SHA256_HEX)
    baseline_policy_id: Mapped[str] = mapped_column(Text, nullable=False)
    baseline_policy_version: Mapped[int] = mapped_column(Integer, nullable=False)
    target_policy_id: Mapped[str] = mapped_column(Text, nullable=False)
    target_policy_version: Mapped[int] = mapped_column(Integer, nullable=False)
    enforced_policy_id: Mapped[str] = mapped_column(Text, nullable=False)
    enforced_policy_version: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class BlastRadius(Base):
    __tablename__ = "blast_radius"
    __table_args__ = (
        PrimaryKeyConstraint("execution_id", name="pk_blast_radius"),
        ForeignKeyConstraint(
            ["execution_id", "eval_config_version"],
            ["agent.execution.id", "agent.execution.eval_config_version"],
            name="fk_blast_radius_execution",
        ),
        ForeignKeyConstraint(
            ["eval_config_version"],
            ["eval.eval_config.version"],
            name="fk_blast_radius_eval_config",
        ),
        {"schema": "eval"},
    )

    execution_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    eval_config_version: Mapped[str] = domain_column(VERSION_LABEL)
    u_attempted: Mapped[int] = mapped_column(Integer, nullable=False)
    u_allowed: Mapped[int] = mapped_column(Integer, nullable=False)
    r_public: Mapped[int] = mapped_column(Integer, nullable=False)
    r_private: Mapped[int] = mapped_column(Integer, nullable=False)
    r_sensitive: Mapped[int] = mapped_column(Integer, nullable=False)
    x_attempted: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    x_succeeded: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    v: Mapped[int] = mapped_column(Integer, nullable=False)
    tool_calls: Mapped[int] = mapped_column(Integer, nullable=False)
    legit_calls: Mapped[int] = mapped_column(Integer, nullable=False)
    false_blocks: Mapped[int] = mapped_column(Integer, nullable=False)
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    label: Mapped[str] = mapped_column(pg_enum("br_label"), nullable=False)
    attack_attempted: Mapped[bool] = mapped_column(Boolean, nullable=False)
    attack_succeeded: Mapped[bool] = mapped_column(Boolean, nullable=False)
    task_succeeded: Mapped[bool] = mapped_column(Boolean, nullable=False)
    had_enforced_deny: Mapped[bool] = mapped_column(Boolean, nullable=False)
    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class EvaluationResult(Base):
    __tablename__ = "evaluation_result"
    __table_args__ = (
        PrimaryKeyConstraint("pair_id", name="pk_evaluation_result"),
        ForeignKeyConstraint(
            ["pair_id", "n_requested"],
            ["eval.replay_pair.id", "eval.replay_pair.repetitions"],
            name="fk_evaluation_result_pair",
        ),
        {"schema": "eval"},
    )

    pair_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    validity: Mapped[str] = mapped_column(pg_enum("pair_validity"), nullable=False)
    drift_details: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    n_requested: Mapped[int] = mapped_column(Integer, nullable=False)
    n_valid: Mapped[int] = mapped_column(Integer, nullable=False)
    n_excluded: Mapped[int] = mapped_column(Integer, nullable=False)
    baseline_metrics: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    protected_metrics: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    deltas: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    single_observation: Mapped[bool] = mapped_column(Boolean, nullable=False)
    limitation_disclosure: Mapped[str] = mapped_column(Text, nullable=False)
    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
