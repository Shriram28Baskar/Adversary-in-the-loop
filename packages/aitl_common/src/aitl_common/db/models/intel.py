"""intel schema: attack sessions through scenarios (migrations 0004-0007).

Provenance (PRD FR-045a) is enforced by NOT NULL and composite foreign keys:
session-bound links carry ``session_id``; ``source_type`` flows from
``AttackSession`` to ``AbstractedThreatPattern`` to ``Scenario`` (FR-045d); a
``Scenario``'s only attack-origin key is ``threat_pattern_id`` (FR-010c).
"""

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
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from aitl_common.db.models.base import Base
from aitl_common.db.types import (
    SHA256_HEX,
    UNTRUSTED_TEXT,
    VERSION_LABEL,
    domain_column,
    pg_enum,
)


class AttackSession(Base):
    __tablename__ = "attack_session"
    __table_args__ = (
        PrimaryKeyConstraint("id", name="pk_attack_session"),
        UniqueConstraint(
            "source_type", "cowrie_session_id", name="uq_attack_session_source_session"
        ),
        UniqueConstraint("id", "source_type", name="uq_attack_session_id_source_type"),
        ForeignKeyConstraint(
            ["first_raw_record_id"],
            ["intel_raw.raw_ingest_record.id"],
            name="fk_attack_session_first_raw_record",
        ),
        {"schema": "intel"},
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, server_default=func.gen_random_uuid())
    source_type: Mapped[str] = mapped_column(pg_enum("source_type"), nullable=False)
    cowrie_session_id: Mapped[str] = domain_column(UNTRUSTED_TEXT)
    src_ip: Mapped[str] = mapped_column(INET, nullable=False)
    src_port: Mapped[int] = mapped_column(Integer, nullable=False)
    first_event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    first_raw_record_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class AttackEvent(Base):
    __tablename__ = "attack_event"
    __table_args__ = (
        PrimaryKeyConstraint("id", name="pk_attack_event"),
        UniqueConstraint("raw_record_id", name="uq_attack_event_raw_record"),
        UniqueConstraint("session_id", "seq", name="uq_attack_event_session_seq"),
        UniqueConstraint("id", "session_id", name="uq_attack_event_id_session"),
        ForeignKeyConstraint(
            ["session_id"], ["intel.attack_session.id"], name="fk_attack_event_session"
        ),
        ForeignKeyConstraint(
            ["raw_record_id"], ["intel_raw.raw_ingest_record.id"], name="fk_attack_event_raw_record"
        ),
        Index("ix_attack_event_session_occurred_at", "session_id", "occurred_at"),
        {"schema": "intel"},
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, server_default=func.gen_random_uuid())
    session_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    raw_record_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[str] = mapped_column(pg_enum("event_type"), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    raw_text: Mapped[str] = domain_column(UNTRUSTED_TEXT)
    normalized_text: Mapped[str] = domain_column(UNTRUSTED_TEXT)
    truncated: Mapped[bool] = mapped_column(Boolean, nullable=False)
    username: Mapped[str | None] = domain_column(UNTRUSTED_TEXT, nullable=True)
    attempted_secret: Mapped[str | None] = domain_column(UNTRUSTED_TEXT, nullable=True)
    artifact_sha256: Mapped[str | None] = domain_column(SHA256_HEX, nullable=True)
    artifact_size: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class AttackerBehavior(Base):
    __tablename__ = "attacker_behavior"
    __table_args__ = (
        PrimaryKeyConstraint("id", name="pk_attacker_behavior"),
        UniqueConstraint("session_id", "ordinal", name="uq_attacker_behavior_session_ordinal"),
        UniqueConstraint("id", "session_id", name="uq_attacker_behavior_id_session"),
        ForeignKeyConstraint(
            ["session_id"], ["intel.attack_session.id"], name="fk_attacker_behavior_session"
        ),
        {"schema": "intel"},
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, server_default=func.gen_random_uuid())
    session_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    phase: Mapped[str] = mapped_column(pg_enum("behavior_phase"), nullable=False)
    phase_rules_version: Mapped[str] = domain_column(VERSION_LABEL)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ended_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class BehaviorEvent(Base):
    __tablename__ = "behavior_event"
    __table_args__ = (
        PrimaryKeyConstraint("behavior_id", "event_id", name="pk_behavior_event"),
        ForeignKeyConstraint(
            ["behavior_id", "session_id"],
            ["intel.attacker_behavior.id", "intel.attacker_behavior.session_id"],
            name="fk_behavior_event_behavior",
        ),
        ForeignKeyConstraint(
            ["event_id", "session_id"],
            ["intel.attack_event.id", "intel.attack_event.session_id"],
            name="fk_behavior_event_event",
        ),
        Index("ix_behavior_event_event_id", "event_id"),
        {"schema": "intel"},
    )

    behavior_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    event_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    session_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)


class TTP(Base):
    __tablename__ = "ttp"
    __table_args__ = (
        PrimaryKeyConstraint("id", name="pk_ttp"),
        UniqueConstraint("id", "session_id", name="uq_ttp_id_session"),
        ForeignKeyConstraint(["session_id"], ["intel.attack_session.id"], name="fk_ttp_session"),
        ForeignKeyConstraint(
            ["behavior_id", "session_id"],
            ["intel.attacker_behavior.id", "intel.attacker_behavior.session_id"],
            name="fk_ttp_behavior",
        ),
        Index("ix_ttp_session_id", "session_id"),
        Index("ix_ttp_behavior_id", "behavior_id"),
        {"schema": "intel"},
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, server_default=func.gen_random_uuid())
    session_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    behavior_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    label: Mapped[str] = mapped_column(Text, nullable=False)
    mapping_status: Mapped[str] = mapped_column(pg_enum("mapping_status"), nullable=False)
    tactic_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence: Mapped[Decimal] = mapped_column(Numeric(3, 2), nullable=False)
    rule_id: Mapped[str] = mapped_column(Text, nullable=False)
    ttp_rules_version: Mapped[str] = domain_column(VERSION_LABEL)
    mapping_version: Mapped[str] = domain_column(VERSION_LABEL)
    first_event_seq: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class TTPTechnique(Base):
    __tablename__ = "ttp_technique"
    __table_args__ = (
        PrimaryKeyConstraint("ttp_id", "technique_id", name="pk_ttp_technique"),
        ForeignKeyConstraint(["ttp_id"], ["intel.ttp.id"], name="fk_ttp_technique_ttp"),
        {"schema": "intel"},
    )

    ttp_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    technique_id: Mapped[str] = mapped_column(Text)


class AbstractedThreatPattern(Base):
    __tablename__ = "abstracted_threat_pattern"
    __table_args__ = (
        PrimaryKeyConstraint("id", name="pk_abstracted_threat_pattern"),
        UniqueConstraint(
            "session_id",
            "rule_id",
            "abstraction_table_version",
            name="uq_abstracted_threat_pattern_rule",
        ),
        UniqueConstraint("id", "source_type", name="uq_abstracted_threat_pattern_id_source_type"),
        UniqueConstraint("id", "session_id", name="uq_abstracted_threat_pattern_id_session"),
        ForeignKeyConstraint(
            ["session_id", "source_type"],
            ["intel.attack_session.id", "intel.attack_session.source_type"],
            name="fk_abstracted_threat_pattern_session",
        ),
        {"schema": "intel"},
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, server_default=func.gen_random_uuid())
    session_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    source_type: Mapped[str] = mapped_column(pg_enum("source_type"), nullable=False)
    rule_id: Mapped[str] = mapped_column(Text, nullable=False)
    abstraction_table_version: Mapped[str] = domain_column(VERSION_LABEL)
    objective: Mapped[str] = mapped_column(pg_enum("objective"), nullable=False)
    target_tier: Mapped[str] = mapped_column(pg_enum("target_tier"), nullable=False)
    movement: Mapped[str] = mapped_column(pg_enum("movement"), nullable=False)
    tool_categories: Mapped[list[str]] = mapped_column(
        ARRAY(pg_enum("tool_category")), nullable=False
    )
    tactics: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False)
    techniques: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class ThreatPatternSource(Base):
    __tablename__ = "threat_pattern_source"
    __table_args__ = (
        PrimaryKeyConstraint("pattern_id", "ordinal", name="pk_threat_pattern_source"),
        UniqueConstraint("pattern_id", "ttp_id", name="uq_threat_pattern_source_ttp"),
        ForeignKeyConstraint(
            ["pattern_id", "session_id"],
            ["intel.abstracted_threat_pattern.id", "intel.abstracted_threat_pattern.session_id"],
            name="fk_threat_pattern_source_pattern",
        ),
        ForeignKeyConstraint(
            ["ttp_id", "session_id"],
            ["intel.ttp.id", "intel.ttp.session_id"],
            name="fk_threat_pattern_source_ttp",
        ),
        Index("ix_threat_pattern_source_ttp_id", "ttp_id"),
        {"schema": "intel"},
    )

    pattern_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    ordinal: Mapped[int] = mapped_column(Integer)
    ttp_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    session_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)


class Scenario(Base):
    """Immutable scenario version; only ``status`` moves, forward only (FR-012, FR-015)."""

    APPEND_ONLY: ClassVar[bool] = False
    __tablename__ = "scenario"
    __table_args__ = (
        PrimaryKeyConstraint("scenario_id", "version", name="pk_scenario"),
        UniqueConstraint(
            "scenario_id", "version", "fixture_set_version", name="uq_scenario_fixture_set"
        ),
        ForeignKeyConstraint(
            ["threat_pattern_id", "source_type"],
            ["intel.abstracted_threat_pattern.id", "intel.abstracted_threat_pattern.source_type"],
            name="fk_scenario_threat_pattern",
        ),
        ForeignKeyConstraint(
            ["agent_task_id", "agent_task_version"],
            ["agent.agent_task.task_id", "agent.agent_task.version"],
            name="fk_scenario_agent_task",
        ),
        ForeignKeyConstraint(
            ["fixture_set_version", "target_asset_id"],
            ["agent.data_asset.fixture_set_version", "agent.data_asset.asset_id"],
            name="fk_scenario_target_asset",
        ),
        Index("ix_scenario_threat_pattern_id", "threat_pattern_id"),
        Index("ix_scenario_status", "status"),
        {"schema": "intel"},
    )

    scenario_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    version: Mapped[int] = mapped_column(Integer)
    threat_pattern_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    source_type: Mapped[str] = mapped_column(pg_enum("source_type"), nullable=False)
    template_id: Mapped[str] = mapped_column(Text, nullable=False)
    template_library_version: Mapped[str] = domain_column(VERSION_LABEL)
    params: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    agent_task_id: Mapped[str] = mapped_column(Text, nullable=False)
    agent_task_version: Mapped[int] = mapped_column(Integer, nullable=False)
    fixture_set_version: Mapped[str] = domain_column(VERSION_LABEL)
    entry_point_type: Mapped[str] = mapped_column(pg_enum("entry_point_type"), nullable=False)
    entry_point_path: Mapped[str] = mapped_column(Text, nullable=False)
    poisoned_content: Mapped[str] = mapped_column(Text, nullable=False)
    target_asset_id: Mapped[str] = mapped_column(Text, nullable=False)
    objective: Mapped[str] = mapped_column(pg_enum("objective"), nullable=False)
    expected_outcome: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    task_scope: Mapped[Any] = mapped_column(JSONB, nullable=False)
    legitimate_calls: Mapped[Any] = mapped_column(JSONB, nullable=False)
    task_success: Mapped[Any] = mapped_column(JSONB, nullable=False)
    attack_success: Mapped[Any] = mapped_column(JSONB, nullable=False)
    content_sha256: Mapped[str] = domain_column(SHA256_HEX)
    status: Mapped[str] = mapped_column(
        pg_enum("scenario_status"), nullable=False, server_default="generated"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class ScenarioStep(Base):
    __tablename__ = "scenario_step"
    __table_args__ = (
        PrimaryKeyConstraint("scenario_id", "version", "ordinal", name="pk_scenario_step"),
        ForeignKeyConstraint(
            ["scenario_id", "version"],
            ["intel.scenario.scenario_id", "intel.scenario.version"],
            name="fk_scenario_step_scenario",
        ),
        {"schema": "intel"},
    )

    scenario_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    version: Mapped[int] = mapped_column(Integer)
    ordinal: Mapped[int] = mapped_column(Integer)
    step_type: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
