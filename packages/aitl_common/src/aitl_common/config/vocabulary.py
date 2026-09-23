"""Controlled vocabulary and identifier formats for configuration artifacts.

Every enum here mirrors a PostgreSQL enum from migration 0001
(``aitl_common.db.types.ENUM_LABELS``); a test asserts they are identical, so
configuration can never name a value the database would reject or vice versa.
Identifier and version formats are fixed patterns; nothing is free-form.
"""

from __future__ import annotations

import re
from typing import Annotated, Final, Literal, get_args

from pydantic import Field, StringConstraints

# --- Enums shared with the database (migration 0001) ------------------------------

EventType = Literal[
    "session_connect",
    "client_version",
    "login_failed",
    "login_success",
    "command_input",
    "file_download",
    "file_upload",
    "session_closed",
    "other",
]
BehaviorPhase = Literal[
    "scanning",
    "credential_probing",
    "discovery",
    "credential_file_access",
    "collection",
    "exfiltration_attempt",
    "ingress_transfer",
    "execution",
    "unclassified",
]
Objective = Literal[
    "access_above_authorized_tier", "access_and_exfiltrate", "exfiltrate_collected_data"
]
Tier = Literal["public", "private", "sensitive"]
TargetTier = Literal["private", "sensitive"]
Movement = Literal["none", "internal_to_external"]
ToolCategory = Literal["read", "query", "send"]
EntryPointType = Literal["document_in_fixture"]
AgentKind = Literal["llm", "scripted"]
ToolName = Literal["file_search", "file_read", "database_query", "mock_api"]
DestinationTrust = Literal["internal", "external"]
AssetKind = Literal["file", "table", "api_data"]
Decision = Literal["ALLOW", "DENY", "APPROVAL"]
BlastRadiusLabel = Literal["MINIMAL", "LOW", "MODERATE", "HIGH"]

DB_ENUMS: Final[dict[str, object]] = {
    "event_type": EventType,
    "behavior_phase": BehaviorPhase,
    "objective": Objective,
    "tier": Tier,
    "target_tier": TargetTier,
    "movement": Movement,
    "tool_category": ToolCategory,
    "entry_point_type": EntryPointType,
    "agent_kind": AgentKind,
    "tool_name": ToolName,
    "destination_trust": DestinationTrust,
    "asset_kind": AssetKind,
    "decision": Decision,
    "br_label": BlastRadiusLabel,
}

# --- Configuration-only closed sets -----------------------------------------------

# FR-002: the only mock_api endpoints; adding one is a tool-set change.
MockEndpoint = Literal["directory_lookup", "send_message"]
# ARCHITECTURE.md §16: database_query filter operators.
FilterOperator = Literal["eq", "contains", "lt", "gt"]
ColumnType = Literal["text", "integer"]
# ARCHITECTURE.md §17: data-flow rules decide only ALLOW or DENY.
DataflowDecision = Literal["ALLOW", "DENY"]
# Engineering plan assumption A1: one provider adapter.
ModelProvider = Literal["anthropic"]
WILDCARD: Final = "*"
Wildcard = Literal["*"]

TOOL_NAMES: Final[tuple[str, ...]] = get_args(ToolName)
MOCK_ENDPOINTS: Final[tuple[str, ...]] = get_args(MockEndpoint)
TIERS: Final[tuple[str, ...]] = get_args(Tier)
TIER_RANK: Final[dict[str, int]] = {"public": 0, "private": 1, "sensitive": 2}

# --- Identifier and version formats -----------------------------------------------


# Matches the public.version_label domain (migration 0001) and is additionally
# tied to the artifact kind, e.g. "attack-mapping-v1".
VERSION_LABEL_RE: Final = r"^[a-z0-9][a-z0-9._-]{0,63}$"
LABEL_VERSION_RE: Final = re.compile(r"^(?P<kind>[a-z][a-z0-9-]*?)-v(?P<n>[1-9][0-9]{0,5})$")

AttackMappingVersion = Annotated[str, StringConstraints(pattern=r"^attack-mapping-v[1-9][0-9]*$")]
PhaseRulesVersion = Annotated[str, StringConstraints(pattern=r"^phase-rules-v[1-9][0-9]*$")]
TtpRulesVersion = Annotated[str, StringConstraints(pattern=r"^ttp-rules-v[1-9][0-9]*$")]
AbstractionTableVersion = Annotated[
    str, StringConstraints(pattern=r"^abstraction-table-v[1-9][0-9]*$")
]
TemplateLibraryVersion = Annotated[
    str, StringConstraints(pattern=r"^template-library-v[1-9][0-9]*$")
]
ToolDefinitionsVersion = Annotated[
    str, StringConstraints(pattern=r"^tool-definitions-v[1-9][0-9]*$")
]
FixtureSetVersion = Annotated[str, StringConstraints(pattern=r"^fixture-set-v[1-9][0-9]*$")]
EvalConfigVersion = Annotated[str, StringConstraints(pattern=r"^eval-v[1-9][0-9]*$")]
AgentLoopVersion = Annotated[str, StringConstraints(pattern=r"^agent-loop-v[1-9][0-9]*$")]
IntVersion = Annotated[int, Field(ge=1, le=999_999)]

TacticId = Annotated[str, StringConstraints(pattern=r"^TA[0-9]{4}$")]
TechniqueId = Annotated[str, StringConstraints(pattern=r"^T[0-9]{4}(?:\.[0-9]{3})?$")]
AttackElementId = Annotated[
    str, StringConstraints(pattern=r"^(?:TA[0-9]{4}|T[0-9]{4}(?:\.[0-9]{3})?)$")
]
TtpLabel = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
PhaseRuleId = Annotated[str, StringConstraints(pattern=r"^PR-[0-9]{2}$")]
TtpRuleId = Annotated[str, StringConstraints(pattern=r"^TR-[0-9]{2}$")]
AbstractionRuleId = Annotated[str, StringConstraints(pattern=r"^AR-[1-9][0-9]*$")]
TemplateId = Annotated[str, StringConstraints(pattern=r"^T-[0-9]{2}$")]
TaskId = Annotated[str, StringConstraints(pattern=r"^TK-[1-9][0-9]*$")]
AgentId = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
AgentRole = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,31}$")]
PolicyId = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9-]{0,63}$")]
PolicyRuleId = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9-]{0,63}$")]
PromptId = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
StepId = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9-]{0,63}$")]
ModelId = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9.-]{0,63}$")]
# Asset IDs are "<kind prefix>:<locator>" (see schemas.fixtures).
AssetId = Annotated[
    str,
    StringConstraints(
        pattern=r"^(?:file:/[a-z0-9_./-]{1,255}|table:[a-z][a-z0-9_]{0,62}|api:[a-z][a-z0-9_]{0,62})$"
    ),
]
# Canonical fixture path: absolute, lowercase, no "..", no "//", no trailing "/".
FixturePath = Annotated[
    str,
    StringConstraints(pattern=r"^(?:/[a-z0-9_-][a-z0-9_.-]{0,63}){1,8}$", max_length=256),
]
TableName = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,62}$")]
ColumnName = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,62}$")]
ArgumentName = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,31}$")]
# A command or argument token as produced by whitespace tokenization (P4/P5).
Token = Annotated[str, StringConstraints(pattern=r"^[^\s]{1,64}$")]

ASSET_PREFIX: Final[dict[str, str]] = {"file": "file:", "table": "table:", "api_data": "api:"}


def asset_id_for(kind: str, locator: str) -> str:
    return f"{ASSET_PREFIX[kind]}{locator}"
