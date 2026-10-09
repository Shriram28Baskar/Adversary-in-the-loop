"""Scenario writer isolation (ADR-021; PRD FR-010c, FR-011).

intel_svc reads attacker-derived text (intel_raw, attack_event, ...). Holding
INSERT on intel.scenario / intel.scenario_step would give it a path to create
scenarios around the Adversary Abstraction -> Scenario Generation boundary.
Only scenario_gen, which has no read access to attacker-text tables, may create
scenarios. intel_svc keeps SELECT on intel.* and column-level
UPDATE(status) on intel.scenario for the review gate (FR-015).

Revision ID: 0013
Revises: 0012
"""

from __future__ import annotations

from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("REVOKE INSERT ON intel.scenario, intel.scenario_step FROM intel_svc")


def downgrade() -> None:
    op.execute("GRANT INSERT ON intel.scenario, intel.scenario_step TO intel_svc")
