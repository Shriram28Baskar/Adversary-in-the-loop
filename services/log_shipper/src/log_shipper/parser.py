"""The shipper's line parser: the shared strict Cowrie parser (PRD FR-005, FR-013, FR-048).

The parser lives in ``aitl_common.telemetry.cowrie`` so intel-service
promotion re-validates staged lines with exactly the same rules (P4), rather
than a second implementation.
"""

from __future__ import annotations

from aitl_common.telemetry.cowrie import EVENTS, MAX_LINE_BYTES, Accepted, Rejected, parse_line

__all__ = ["EVENTS", "MAX_LINE_BYTES", "Accepted", "Rejected", "parse_line"]
