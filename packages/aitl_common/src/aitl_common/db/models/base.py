"""Declarative base for every table (ARCHITECTURE.md §24).

``APPEND_ONLY`` marks FR-044 tables (and join/step/outbox tables of immutable
parents): no runtime role may UPDATE or DELETE them, and the database rejects
those statements with triggers. Application code must never issue UPDATE or
DELETE against them (static test: tests/security/test_append_only_static.py).
"""

from __future__ import annotations

from typing import ClassVar

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    metadata = MetaData()
    APPEND_ONLY: ClassVar[bool] = True
    """True for append-only tables; False only for intel.scenario and agent.execution."""
