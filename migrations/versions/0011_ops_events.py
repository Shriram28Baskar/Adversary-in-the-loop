"""ops.events outbox (ARCHITECTURE.md §8, §26; ADR-002).

Append-only (0012). Event payloads are for UI/notification, not the audit
record of truth; arguments are hashed in payloads (§26).

Revision ID: 0011
Revises: 0010
"""

from __future__ import annotations

from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE ops.events (
        id bigint GENERATED ALWAYS AS IDENTITY,
        event_id uuid NOT NULL DEFAULT gen_random_uuid(),
        event_type text NOT NULL,
        correlation_id uuid NOT NULL,
        execution_id uuid,
        pair_id uuid,
        occurred_at timestamptz NOT NULL,
        payload jsonb NOT NULL,
        CONSTRAINT pk_events PRIMARY KEY (id),
        CONSTRAINT uq_events_event_id UNIQUE (event_id),
        CONSTRAINT ck_events_event_type CHECK (event_type ~ '^[A-Z][A-Za-z]+[.]v[0-9]+$')
    );
    """)


def downgrade() -> None:
    op.execute("DROP TABLE ops.events")
