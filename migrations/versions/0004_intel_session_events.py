"""intel.attack_session and intel.attack_event (PRD FR-005, FR-005a, FR-013, FR-045a).

Attacker-derived text uses the untrusted_text domain with the FR-013 caps:
raw_text <= 4096 bytes (truncation flagged), normalized_text <= 1024 chars.
source_type is set from the ingestion mode, never from log content (FR-005).
UNIQUE (id, source_type) and UNIQUE (id, session_id) exist so downstream
composite foreign keys can carry provenance without triggers.

Revision ID: 0004
Revises: 0003
"""

from __future__ import annotations

from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE intel.attack_session (
        id uuid NOT NULL DEFAULT gen_random_uuid(),
        source_type public.source_type NOT NULL,
        cowrie_session_id public.untrusted_text NOT NULL,
        src_ip inet NOT NULL,
        src_port integer NOT NULL,
        first_event_at timestamptz NOT NULL,
        first_raw_record_id bigint NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT pk_attack_session PRIMARY KEY (id),
        CONSTRAINT uq_attack_session_source_session UNIQUE (source_type, cowrie_session_id),
        CONSTRAINT uq_attack_session_id_source_type UNIQUE (id, source_type),
        CONSTRAINT fk_attack_session_first_raw_record
            FOREIGN KEY (first_raw_record_id) REFERENCES intel_raw.raw_ingest_record (id),
        CONSTRAINT ck_attack_session_cowrie_session_id
            CHECK (octet_length(cowrie_session_id) <= 64),
        CONSTRAINT ck_attack_session_src_port CHECK (src_port BETWEEN 0 AND 65535)
    );

    CREATE TABLE intel.attack_event (
        id uuid NOT NULL DEFAULT gen_random_uuid(),
        session_id uuid NOT NULL,
        raw_record_id bigint NOT NULL,
        seq integer NOT NULL,
        event_type public.event_type NOT NULL,
        occurred_at timestamptz NOT NULL,
        raw_text public.untrusted_text NOT NULL,
        normalized_text public.untrusted_text NOT NULL,
        truncated boolean NOT NULL,
        username public.untrusted_text,
        attempted_secret public.untrusted_text,
        artifact_sha256 public.sha256_hex,
        artifact_size bigint,
        created_at timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT pk_attack_event PRIMARY KEY (id),
        CONSTRAINT uq_attack_event_raw_record UNIQUE (raw_record_id),
        CONSTRAINT uq_attack_event_session_seq UNIQUE (session_id, seq),
        CONSTRAINT uq_attack_event_id_session UNIQUE (id, session_id),
        CONSTRAINT fk_attack_event_session
            FOREIGN KEY (session_id) REFERENCES intel.attack_session (id),
        CONSTRAINT fk_attack_event_raw_record
            FOREIGN KEY (raw_record_id) REFERENCES intel_raw.raw_ingest_record (id),
        CONSTRAINT ck_attack_event_seq CHECK (seq >= 1),
        CONSTRAINT ck_attack_event_raw_text CHECK (octet_length(raw_text) <= 4096),
        CONSTRAINT ck_attack_event_normalized_text CHECK (
            char_length(normalized_text) <= 1024 AND octet_length(normalized_text) <= 4096
        ),
        CONSTRAINT ck_attack_event_username CHECK (octet_length(username) <= 256),
        CONSTRAINT ck_attack_event_attempted_secret CHECK (octet_length(attempted_secret) <= 256),
        CONSTRAINT ck_attack_event_artifact_size CHECK (artifact_size >= 0)
    );
    CREATE INDEX ix_attack_event_session_occurred_at
        ON intel.attack_event (session_id, occurred_at);
    """)


def downgrade() -> None:
    op.execute("""
    DROP TABLE intel.attack_event;
    DROP TABLE intel.attack_session;
    """)
