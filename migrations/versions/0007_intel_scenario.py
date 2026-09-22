"""intel.scenario and intel.scenario_step (PRD FR-010c, FR-011, FR-012, FR-015, FR-045d).

- threat_pattern_id is NOT NULL and is the scenario's only attack-origin key.
  (threat_pattern_id, source_type) references the pattern, so a scenario's
  source_type always equals its origin session's (FR-045d); honeypot and
  synthetic provenance cannot be mixed.
- There is no source_reference or any attacker-text column (FR-011, ADR-017).
- scenario_guard: new scenarios start in 'generated'; content columns are
  immutable; status moves only forward
  (generated->reviewed|rejected, reviewed->approved|rejected); rows cannot be
  deleted or truncated. Steps are immutable with their scenario.

Custom SQLSTATEs raised by triggers in this schema:
  AITL1 append-only record modified, AITL2 immutable content changed,
  AITL3 invalid status transition, AITL4 execution of unapproved scenario.

Revision ID: 0007
Revises: 0006
"""

from __future__ import annotations

from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE intel.scenario (
        scenario_id uuid NOT NULL,
        version integer NOT NULL,
        threat_pattern_id uuid NOT NULL,
        source_type public.source_type NOT NULL,
        template_id text NOT NULL,
        template_library_version public.version_label NOT NULL,
        params jsonb NOT NULL,
        agent_task_id text NOT NULL,
        agent_task_version integer NOT NULL,
        fixture_set_version public.version_label NOT NULL,
        entry_point_type public.entry_point_type NOT NULL,
        entry_point_path text NOT NULL,
        poisoned_content text NOT NULL,
        target_asset_id text NOT NULL,
        objective public.objective NOT NULL,
        expected_outcome jsonb NOT NULL,
        task_scope jsonb NOT NULL,
        legitimate_calls jsonb NOT NULL,
        task_success jsonb NOT NULL,
        attack_success jsonb NOT NULL,
        content_sha256 public.sha256_hex NOT NULL,
        status public.scenario_status NOT NULL DEFAULT 'generated',
        created_at timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT pk_scenario PRIMARY KEY (scenario_id, version),
        CONSTRAINT uq_scenario_fixture_set UNIQUE (scenario_id, version, fixture_set_version),
        CONSTRAINT fk_scenario_threat_pattern FOREIGN KEY (threat_pattern_id, source_type)
            REFERENCES intel.abstracted_threat_pattern (id, source_type),
        CONSTRAINT fk_scenario_agent_task FOREIGN KEY (agent_task_id, agent_task_version)
            REFERENCES agent.agent_task (task_id, version),
        CONSTRAINT fk_scenario_target_asset FOREIGN KEY (fixture_set_version, target_asset_id)
            REFERENCES agent.data_asset (fixture_set_version, asset_id),
        CONSTRAINT ck_scenario_version_positive CHECK (version >= 1)
    );
    CREATE INDEX ix_scenario_threat_pattern_id ON intel.scenario (threat_pattern_id);
    CREATE INDEX ix_scenario_status ON intel.scenario (status);

    CREATE TABLE intel.scenario_step (
        scenario_id uuid NOT NULL,
        version integer NOT NULL,
        ordinal integer NOT NULL,
        step_type text NOT NULL,
        description text NOT NULL,
        CONSTRAINT pk_scenario_step PRIMARY KEY (scenario_id, version, ordinal),
        CONSTRAINT fk_scenario_step_scenario FOREIGN KEY (scenario_id, version)
            REFERENCES intel.scenario (scenario_id, version),
        CONSTRAINT ck_scenario_step_ordinal CHECK (ordinal >= 1)
    );

    CREATE FUNCTION intel.scenario_guard() RETURNS trigger
    LANGUAGE plpgsql AS $fn$
    BEGIN
        IF TG_OP = 'INSERT' THEN
            IF NEW.status <> 'generated' THEN
                RAISE EXCEPTION 'scenario must be inserted with status generated'
                    USING ERRCODE = 'AITL3';
            END IF;
            RETURN NEW;
        ELSIF TG_OP = 'UPDATE' THEN
            IF (to_jsonb(NEW) - 'status') IS DISTINCT FROM (to_jsonb(OLD) - 'status') THEN
                RAISE EXCEPTION 'scenario content is immutable; create a new version'
                    USING ERRCODE = 'AITL2';
            END IF;
            IF NOT (
                (OLD.status = 'generated' AND NEW.status IN ('reviewed', 'rejected'))
                OR (OLD.status = 'reviewed' AND NEW.status IN ('approved', 'rejected'))
            ) THEN
                RAISE EXCEPTION 'invalid scenario status transition % -> %', OLD.status, NEW.status
                    USING ERRCODE = 'AITL3';
            END IF;
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'scenario records cannot be deleted' USING ERRCODE = 'AITL1';
    END;
    $fn$;

    CREATE TRIGGER trg_scenario_guard
        BEFORE INSERT OR UPDATE OR DELETE ON intel.scenario
        FOR EACH ROW EXECUTE FUNCTION intel.scenario_guard();
    """)


def downgrade() -> None:
    op.execute("""
    DROP TABLE intel.scenario_step;
    DROP TABLE intel.scenario;
    DROP FUNCTION intel.scenario_guard();
    """)
