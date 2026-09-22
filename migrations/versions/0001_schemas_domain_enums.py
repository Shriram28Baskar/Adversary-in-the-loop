"""Schemas, shared domains, and enum types (ARCHITECTURE.md §24; PRD FR-005a).

Revision ID: 0001
Revises:
"""

from __future__ import annotations

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

SCHEMAS = ("intel_raw", "intel", "agent", "security", "eval", "ops")

# Shared types live in the public schema (owned by aitl_owner as database owner)
# because several domain schemas use them.
ENUMS: dict[str, tuple[str, ...]] = {
    "source_type": ("honeypot", "synthetic"),
    "ingest_mode": ("live", "fixture"),
    "raw_kind": ("event", "heartbeat"),
    "quarantine_stage": ("shipper_parse", "shipper_validate", "promotion"),
    "event_type": (
        "session_connect",
        "client_version",
        "login_failed",
        "login_success",
        "command_input",
        "file_download",
        "file_upload",
        "session_closed",
        "other",
    ),
    "behavior_phase": (
        "scanning",
        "credential_probing",
        "discovery",
        "credential_file_access",
        "collection",
        "exfiltration_attempt",
        "ingress_transfer",
        "execution",
        "unclassified",
    ),
    "mapping_status": ("mapped", "unmapped"),
    "objective": (
        "access_above_authorized_tier",
        "access_and_exfiltrate",
        "exfiltrate_collected_data",
    ),
    "tier": ("public", "private", "sensitive"),
    "target_tier": ("private", "sensitive"),
    "movement": ("none", "internal_to_external"),
    "tool_category": ("read", "query", "send"),
    "scenario_status": ("generated", "reviewed", "approved", "rejected"),
    "entry_point_type": ("document_in_fixture",),
    "agent_kind": ("llm", "scripted"),
    "tool_name": ("file_search", "file_read", "database_query", "mock_api"),
    "destination_trust": ("internal", "external"),
    "asset_kind": ("file", "table", "api_data"),
    "run_role": ("single", "baseline", "protected"),
    "lifecycle": ("pending", "running", "completed", "errored", "killed"),
    "error_class": (
        "sandbox_crash",
        "timeout",
        "llm_provider_error",
        "gateway_fail_closed",
        "audit_write_failure",
        "teardown_failure",
    ),
    "termination_reason": ("agent_finished", "step_limit"),
    "decision": ("ALLOW", "DENY", "APPROVAL"),
    "reason_code": (
        "permission_allow",
        "permission_deny",
        "permission_approval",
        "dataflow_deny",
        "no_rule",
        "validation_error",
        "step_limit",
        "system_error",
        "approval_unavailable_mvp",
    ),
    "approval_resolution": ("auto_denied",),
    "flow_kind": ("source", "sink_match"),
    "marker_kind": ("canary", "fingerprint"),
    "failure_class": ("policy_error", "timeout", "db_write_failure", "environment_error", "internal"),
    "validation_status": ("valid", "rejected"),
    "model_call_status": ("ok", "provider_error", "budget_exceeded"),
    "br_label": ("MINIMAL", "LOW", "MODERATE", "HIGH"),
    "pair_validity": ("valid", "invalid_drift"),
}


def upgrade() -> None:
    for schema in SCHEMAS:
        op.execute(f"CREATE SCHEMA {schema}")

    # Attacker- and LLM-derived text is typed as untrusted at the schema level
    # (FR-005a). Column-specific caps are added as table CHECK constraints.
    op.execute(
        "CREATE DOMAIN public.untrusted_text AS text "
        "CONSTRAINT untrusted_text_max_bytes CHECK (octet_length(VALUE) <= 65536)"
    )
    op.execute(
        "CREATE DOMAIN public.sha256_hex AS text "
        "CONSTRAINT sha256_hex_format CHECK (VALUE ~ '^[0-9a-f]{64}$')"
    )
    op.execute(
        "CREATE DOMAIN public.version_label AS text "
        "CONSTRAINT version_label_format CHECK (VALUE ~ '^[a-z0-9][a-z0-9._-]{0,63}$')"
    )
    for name, labels in ENUMS.items():
        values = ", ".join(f"'{label}'" for label in labels)
        op.execute(f"CREATE TYPE public.{name} AS ENUM ({values})")


def downgrade() -> None:
    for name in reversed(ENUMS):
        op.execute(f"DROP TYPE public.{name}")
    for domain in ("version_label", "sha256_hex", "untrusted_text"):
        op.execute(f"DROP DOMAIN public.{domain}")
    for schema in reversed(SCHEMAS):
        op.execute(f"DROP SCHEMA {schema}")
