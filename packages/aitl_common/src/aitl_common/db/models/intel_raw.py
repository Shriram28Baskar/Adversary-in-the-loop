"""intel_raw schema: one-way telemetry staging (migration 0003)."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKeyConstraint,
    Identity,
    Index,
    PrimaryKeyConstraint,
    Text,
    Uuid,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from aitl_common.db.models.base import Base
from aitl_common.db.types import SHA256_HEX, UNTRUSTED_TEXT, domain_column, pg_enum


class RawIngestRecord(Base):
    __tablename__ = "raw_ingest_record"
    __table_args__ = (
        PrimaryKeyConstraint("id", name="pk_raw_ingest_record"),
        # Replay-safe ingestion (migration 0014): one event row per line and mode.
        Index(
            "ux_raw_ingest_record_event",
            "ingest_mode",
            "payload_sha256",
            unique=True,
            postgresql_where=text("kind = 'event'"),
        ),
        {"schema": "intel_raw"},
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True))
    kind: Mapped[str] = mapped_column(pg_enum("raw_kind"), nullable=False)
    ingest_mode: Mapped[str] = mapped_column(pg_enum("ingest_mode"), nullable=False)
    source_ref: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[str] = domain_column(UNTRUSTED_TEXT)
    payload_sha256: Mapped[str] = domain_column(SHA256_HEX)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class QuarantineRecord(Base):
    __tablename__ = "quarantine_record"
    __table_args__ = (
        PrimaryKeyConstraint("id", name="pk_quarantine_record"),
        ForeignKeyConstraint(
            ["raw_record_id"],
            ["intel_raw.raw_ingest_record.id"],
            name="fk_quarantine_record_raw_record",
        ),
        Index("ix_quarantine_record_raw_record_id", "raw_record_id"),
        # Replay-safe shipper quarantine (migration 0014).
        Index(
            "ux_quarantine_record_shipper",
            "stage",
            "reason_code",
            text("sha256(payload::text::bytea)"),
            unique=True,
            postgresql_where=text("raw_record_id IS NULL"),
        ),
        {"schema": "intel_raw"},
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, server_default=func.gen_random_uuid())
    raw_record_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    stage: Mapped[str] = mapped_column(pg_enum("quarantine_stage"), nullable=False)
    reason_code: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[str] = domain_column(UNTRUSTED_TEXT)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
