"""Behavior reconstruction and TTP tables (PRD FR-006–FR-010, FR-045a).

behavior_event carries session_id with composite foreign keys to both sides,
so an event can only be linked to a behavior of its own session; ttp likewise
references its behavior within the same session. This keeps the provenance
chain from mixing sessions at the database level.

Revision ID: 0005
Revises: 0004
"""

from __future__ import annotations

from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE intel.attacker_behavior (
        id uuid NOT NULL DEFAULT gen_random_uuid(),
        session_id uuid NOT NULL,
        ordinal integer NOT NULL,
        phase public.behavior_phase NOT NULL,
        phase_rules_version public.version_label NOT NULL,
        started_at timestamptz NOT NULL,
        ended_at timestamptz NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT pk_attacker_behavior PRIMARY KEY (id),
        CONSTRAINT uq_attacker_behavior_session_ordinal UNIQUE (session_id, ordinal),
        CONSTRAINT uq_attacker_behavior_id_session UNIQUE (id, session_id),
        CONSTRAINT fk_attacker_behavior_session
            FOREIGN KEY (session_id) REFERENCES intel.attack_session (id),
        CONSTRAINT ck_attacker_behavior_ordinal CHECK (ordinal >= 1),
        CONSTRAINT ck_attacker_behavior_interval CHECK (ended_at >= started_at)
    );

    CREATE TABLE intel.behavior_event (
        behavior_id uuid NOT NULL,
        event_id uuid NOT NULL,
        session_id uuid NOT NULL,
        CONSTRAINT pk_behavior_event PRIMARY KEY (behavior_id, event_id),
        CONSTRAINT fk_behavior_event_behavior FOREIGN KEY (behavior_id, session_id)
            REFERENCES intel.attacker_behavior (id, session_id),
        CONSTRAINT fk_behavior_event_event FOREIGN KEY (event_id, session_id)
            REFERENCES intel.attack_event (id, session_id)
    );
    CREATE INDEX ix_behavior_event_event_id ON intel.behavior_event (event_id);

    CREATE TABLE intel.ttp (
        id uuid NOT NULL DEFAULT gen_random_uuid(),
        session_id uuid NOT NULL,
        behavior_id uuid NOT NULL,
        label text NOT NULL,
        mapping_status public.mapping_status NOT NULL,
        tactic_id text,
        confidence numeric(3, 2) NOT NULL,
        rule_id text NOT NULL,
        ttp_rules_version public.version_label NOT NULL,
        mapping_version public.version_label NOT NULL,
        first_event_seq integer NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT pk_ttp PRIMARY KEY (id),
        CONSTRAINT uq_ttp_id_session UNIQUE (id, session_id),
        CONSTRAINT fk_ttp_session FOREIGN KEY (session_id) REFERENCES intel.attack_session (id),
        CONSTRAINT fk_ttp_behavior FOREIGN KEY (behavior_id, session_id)
            REFERENCES intel.attacker_behavior (id, session_id),
        CONSTRAINT ck_ttp_mapping CHECK ((mapping_status = 'mapped') = (tactic_id IS NOT NULL)),
        CONSTRAINT ck_ttp_tactic_id CHECK (tactic_id ~ '^TA[0-9]{4}$'),
        CONSTRAINT ck_ttp_confidence CHECK (confidence >= 0 AND confidence <= 1),
        CONSTRAINT ck_ttp_first_event_seq CHECK (first_event_seq >= 1)
    );
    CREATE INDEX ix_ttp_session_id ON intel.ttp (session_id);
    CREATE INDEX ix_ttp_behavior_id ON intel.ttp (behavior_id);

    CREATE TABLE intel.ttp_technique (
        ttp_id uuid NOT NULL,
        technique_id text NOT NULL,
        CONSTRAINT pk_ttp_technique PRIMARY KEY (ttp_id, technique_id),
        CONSTRAINT fk_ttp_technique_ttp FOREIGN KEY (ttp_id) REFERENCES intel.ttp (id),
        CONSTRAINT ck_ttp_technique_id CHECK (technique_id ~ '^T[0-9]{4}([.][0-9]{3})?$')
    );
    """)


def downgrade() -> None:
    op.execute("""
    DROP TABLE intel.ttp_technique;
    DROP TABLE intel.ttp;
    DROP TABLE intel.behavior_event;
    DROP TABLE intel.attacker_behavior;
    """)
