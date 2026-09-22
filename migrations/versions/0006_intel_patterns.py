"""Adversary Abstraction Layer tables (PRD FR-010a–FR-010c, FR-045a, FR-045d; ADR-016).

- abstracted_threat_pattern carries (session_id, source_type) with a composite
  foreign key to attack_session, so a pattern's source_type always equals its
  originating session's.
- threat_pattern_source links a pattern to its ordered TTP chain; composite
  foreign keys through session_id make a cross-session chain impossible.
- Pattern rows hold only controlled-vocabulary enums, identifiers, versions,
  and the rule rationale copied from the trusted abstraction table (FR-010a).

Revision ID: 0006
Revises: 0005
"""

from __future__ import annotations

from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE intel.abstracted_threat_pattern (
        id uuid NOT NULL DEFAULT gen_random_uuid(),
        session_id uuid NOT NULL,
        source_type public.source_type NOT NULL,
        rule_id text NOT NULL,
        abstraction_table_version public.version_label NOT NULL,
        objective public.objective NOT NULL,
        target_tier public.target_tier NOT NULL,
        movement public.movement NOT NULL,
        tool_categories public.tool_category[] NOT NULL,
        tactics text[] NOT NULL,
        techniques text[] NOT NULL,
        rationale text NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT pk_abstracted_threat_pattern PRIMARY KEY (id),
        CONSTRAINT uq_abstracted_threat_pattern_rule
            UNIQUE (session_id, rule_id, abstraction_table_version),
        CONSTRAINT uq_abstracted_threat_pattern_id_source_type UNIQUE (id, source_type),
        CONSTRAINT uq_abstracted_threat_pattern_id_session UNIQUE (id, session_id),
        CONSTRAINT fk_abstracted_threat_pattern_session FOREIGN KEY (session_id, source_type)
            REFERENCES intel.attack_session (id, source_type),
        CONSTRAINT ck_abstracted_threat_pattern_tool_categories
            CHECK (cardinality(tool_categories) >= 1)
    );

    CREATE TABLE intel.threat_pattern_source (
        pattern_id uuid NOT NULL,
        ordinal integer NOT NULL,
        ttp_id uuid NOT NULL,
        session_id uuid NOT NULL,
        CONSTRAINT pk_threat_pattern_source PRIMARY KEY (pattern_id, ordinal),
        CONSTRAINT uq_threat_pattern_source_ttp UNIQUE (pattern_id, ttp_id),
        CONSTRAINT fk_threat_pattern_source_pattern FOREIGN KEY (pattern_id, session_id)
            REFERENCES intel.abstracted_threat_pattern (id, session_id),
        CONSTRAINT fk_threat_pattern_source_ttp FOREIGN KEY (ttp_id, session_id)
            REFERENCES intel.ttp (id, session_id),
        CONSTRAINT ck_threat_pattern_source_ordinal CHECK (ordinal >= 1)
    );
    CREATE INDEX ix_threat_pattern_source_ttp_id ON intel.threat_pattern_source (ttp_id);
    """)


def downgrade() -> None:
    op.execute("""
    DROP TABLE intel.threat_pattern_source;
    DROP TABLE intel.abstracted_threat_pattern;
    """)
