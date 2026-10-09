"""intel_raw staging tables for the one-way telemetry path (ARCHITECTURE.md §9, §24).

The Log Shipper writes here with the INSERT-only ingest_writer role (FR-004b).
Payloads keep the full sanitized line (up to 64 KiB) so evidence is preserved
even where AttackEvent fields are capped (FR-013).

Revision ID: 0003
Revises: 0002
"""

from __future__ import annotations

from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE intel_raw.raw_ingest_record (
        id bigint GENERATED ALWAYS AS IDENTITY,
        kind public.raw_kind NOT NULL,
        ingest_mode public.ingest_mode NOT NULL,
        source_ref text NOT NULL,
        payload public.untrusted_text NOT NULL,
        payload_sha256 public.sha256_hex NOT NULL,
        received_at timestamptz NOT NULL DEFAULT now(),
        created_at timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT pk_raw_ingest_record PRIMARY KEY (id),
        CONSTRAINT ck_raw_ingest_record_source_ref CHECK (octet_length(source_ref) <= 512)
    );

    CREATE TABLE intel_raw.quarantine_record (
        id uuid NOT NULL DEFAULT gen_random_uuid(),
        raw_record_id bigint,
        stage public.quarantine_stage NOT NULL,
        reason_code text NOT NULL,
        payload public.untrusted_text NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT pk_quarantine_record PRIMARY KEY (id),
        CONSTRAINT fk_quarantine_record_raw_record
            FOREIGN KEY (raw_record_id) REFERENCES intel_raw.raw_ingest_record (id),
        CONSTRAINT ck_quarantine_record_reason_code CHECK (reason_code ~ '^[a-z0-9_.]{1,128}$')
    );
    CREATE INDEX ix_quarantine_record_raw_record_id
        ON intel_raw.quarantine_record (raw_record_id);
    """)


def downgrade() -> None:
    op.execute("""
    DROP TABLE intel_raw.quarantine_record;
    DROP TABLE intel_raw.raw_ingest_record;
    """)
