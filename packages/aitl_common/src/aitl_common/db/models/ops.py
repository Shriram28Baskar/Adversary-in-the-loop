"""ops schema: append-only event outbox (migration 0011; ARCHITECTURE.md §8, §26)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    DateTime,
    Identity,
    PrimaryKeyConstraint,
    Text,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from aitl_common.db.models.base import Base


class OutboxEvent(Base):
    __tablename__ = "events"
    __table_args__ = (
        PrimaryKeyConstraint("id", name="pk_events"),
        UniqueConstraint("event_id", name="uq_events_event_id"),
        {"schema": "ops"},
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True))
    event_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, nullable=False, server_default=func.gen_random_uuid()
    )
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    correlation_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    execution_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    pair_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
