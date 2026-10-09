"""Replay-safe staging keys for the Log Shipper (P3; PRD FR-004b, FR-005, FR-048).

Re-ingesting the same source line - a retried batch after a database outage,
a restarted shipper that lost its offsets, a replayed fixture corpus - must
not create duplicate staging rows, and must not mutate or delete history
(FR-044). Two partial unique indexes make the duplicate insert a no-op:

- ``ux_raw_ingest_record_event``: one ``event`` row per (ingest_mode,
  payload_sha256). The shipper stores each validated line verbatim, so the
  hash identifies the line. Heartbeats are excluded (they repeat by design).
- ``ux_quarantine_record_shipper``: one shipper-stage quarantine row per
  (stage, reason_code, payload hash). Promotion-stage rows (raw_record_id set)
  are not constrained.

The shipper inserts with an *untargeted* ``ON CONFLICT DO NOTHING``, which
needs only the INSERT privilege ingest_writer already has (a targeted conflict
clause or RETURNING would need SELECT). No grant changes.

Revision ID: 0014
Revises: 0013
"""

from __future__ import annotations

from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


# SHA-256 of the payload's exact UTF-8 bytes, as an IMMUTABLE expression (an
# index requirement; convert_to() is only STABLE). A plain ``text::bytea`` cast
# parses backslash escapes and rejects ordinary payloads such as JSON with an
# escaped quote; doubling every backslash first makes decode(..., 'escape')
# return the bytes verbatim, so the digest is injective over payloads.
QUARANTINE_PAYLOAD_DIGEST = (
    r"sha256(decode(replace(payload::text, '\', '\\'), 'escape'))"
)


def upgrade() -> None:
    op.execute(
        "CREATE UNIQUE INDEX ux_raw_ingest_record_event "
        "ON intel_raw.raw_ingest_record (ingest_mode, payload_sha256) WHERE kind = 'event'"
    )
    op.execute(
        "CREATE UNIQUE INDEX ux_quarantine_record_shipper "
        "ON intel_raw.quarantine_record (stage, reason_code, "
        f"{QUARANTINE_PAYLOAD_DIGEST}) "
        "WHERE raw_record_id IS NULL"
    )


def downgrade() -> None:
    op.execute("DROP INDEX intel_raw.ux_quarantine_record_shipper")
    op.execute("DROP INDEX intel_raw.ux_raw_ingest_record_event")
