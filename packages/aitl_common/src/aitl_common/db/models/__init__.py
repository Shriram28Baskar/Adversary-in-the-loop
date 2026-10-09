"""The single authoritative ORM definition of every table (ARCHITECTURE.md §24).

Importing this package registers all tables on ``Base.metadata``.
"""

from aitl_common.db.models import agent, eval, intel, intel_raw, ops, security
from aitl_common.db.models.base import Base

__all__ = ["Base", "agent", "eval", "intel", "intel_raw", "ops", "security"]
