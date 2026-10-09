"""Column type helpers shared by the ORM models.

DDL is owned by the Alembic migrations (``migrations/versions``); these models
are the single authoritative Python mapping of that DDL and are verified
against the migrated database by ``tests/integration/test_orm_ddl_consistency.py``.
``MetaData.create_all`` must never be used to create schema objects.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import Text
from sqlalchemy.dialects.postgresql import ENUM
from sqlalchemy.orm import mapped_column

# Enum labels, in database order (migration 0001).
ENUM_LABELS: dict[str, tuple[str, ...]] = {
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
    "failure_class": (
        "policy_error",
        "timeout",
        "db_write_failure",
        "environment_error",
        "internal",
    ),
    "validation_status": ("valid", "rejected"),
    "model_call_status": ("ok", "provider_error", "budget_exceeded"),
    "br_label": ("MINIMAL", "LOW", "MODERATE", "HIGH"),
    "pair_validity": ("valid", "invalid_drift"),
}

# Domains (migration 0001). Columns typed with a domain carry info["domain"].
UNTRUSTED_TEXT = "untrusted_text"
SHA256_HEX = "sha256_hex"
VERSION_LABEL = "version_label"


def pg_enum(name: str) -> ENUM:
    """The existing PostgreSQL enum type ``public.<name>`` (never created from Python)."""
    return ENUM(*ENUM_LABELS[name], name=name, schema="public", create_type=False)


def domain_column(domain: str, *, nullable: bool = False, **kwargs: Any) -> Any:
    """A text column typed by one of the shared domains."""
    return mapped_column(Text, nullable=nullable, info={"domain": domain}, **kwargs)
