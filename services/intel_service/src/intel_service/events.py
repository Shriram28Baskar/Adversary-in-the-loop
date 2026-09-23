"""Canonical normalized events from re-validated staged telemetry (FR-005, FR-013; ADR-024 D7).

A staged ``RawIngestRecord`` payload is re-validated with the same strict
parser the Log Shipper used (``aitl_common.telemetry.cowrie``) and turned
into a ``NormalizedEvent``:

- ``source_type`` comes only from the record's ``ingest_mode`` - deployment
  configuration - through a constant map, never from the payload (FR-005b).
- ``event_type`` is the parser's format mapping of the Cowrie event ID;
  Cowrie event types outside the enum are ``other``.
- ``raw_text``/``normalized_text`` hold the event's one attacker-supplied text
  field (D7): ``input`` for commands, ``url`` for downloads, ``filename`` for
  uploads, ``version`` for the client version, ``username`` for logins;
  connect, close and ``other`` events carry empty text.
- Usernames and attempted passwords also go into their own columns, capped at
  256 bytes; the password is never copied into ``raw_text``.
- ``src_port`` is read from the ``session_connect`` event only (D6).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final

from aitl_common.telemetry.cowrie import Accepted
from intel_service.sanitize import sanitize, sanitize_field

__all__ = [
    "RAW_TEXT_FIELD",
    "SOURCE_TYPE_BY_MODE",
    "NormalizedEvent",
    "normalize_event",
]

# FR-005 / FR-005b: the only way a source_type is chosen.
SOURCE_TYPE_BY_MODE: Final[Mapping[str, str]] = {"live": "honeypot", "fixture": "synthetic"}

# D7: the attacker-supplied text field stored as raw_text/normalized_text.
RAW_TEXT_FIELD: Final[Mapping[str, str]] = {
    "command_input": "input",
    "file_download": "url",
    "file_upload": "filename",
    "client_version": "version",
    "login_failed": "username",
    "login_success": "username",
}
_LOGIN: Final = frozenset({"login_failed", "login_success"})
_ARTIFACT: Final = frozenset({"file_download", "file_upload"})


@dataclass(frozen=True, slots=True)
class NormalizedEvent:
    raw_record_id: int
    source_type: str
    cowrie_session_id: str
    event_type: str
    occurred_at: datetime
    raw_text: str
    normalized_text: str
    truncated: bool
    username: str | None
    attempted_secret: str | None
    artifact_sha256: str | None
    src_ip: str | None  # canonical textual form, when the event carries one
    src_port: int | None  # session_connect only

    @property
    def tokens(self) -> list[str]:
        """Whitespace tokens of the normalized form (the only input to phase rules)."""
        return self.normalized_text.split()


def _text(fields: Mapping[str, Any], name: str) -> str:
    value = fields.get(name)
    return value if isinstance(value, str) else ""


def normalize_event(raw_record_id: int, ingest_mode: str, accepted: Accepted) -> NormalizedEvent:
    """Build the canonical event. ``ingest_mode`` is the staging row's column value."""
    source_type = SOURCE_TYPE_BY_MODE[ingest_mode]  # KeyError: unknown mode fails closed
    fields = accepted.fields
    text_field = RAW_TEXT_FIELD.get(accepted.event_type)
    text = sanitize(_text(fields, text_field) if text_field else "")
    truncated = text.truncated

    username = attempted_secret = None
    if accepted.event_type in _LOGIN:
        username, cut = sanitize_field(_text(fields, "username"))
        truncated |= cut
        attempted_secret, cut = sanitize_field(_text(fields, "password"))
        truncated |= cut

    artifact_sha256 = None
    if accepted.event_type in _ARTIFACT:
        shasum = fields.get("shasum")
        artifact_sha256 = shasum if isinstance(shasum, str) else None

    src_ip = None
    if isinstance(fields.get("src_ip"), str):
        src_ip = str(ipaddress.ip_address(fields["src_ip"]))  # validated by the parser

    src_port = None
    if accepted.event_type == "session_connect":
        port = fields.get("src_port")
        src_port = port if isinstance(port, int) and not isinstance(port, bool) else None

    return NormalizedEvent(
        raw_record_id=raw_record_id,
        source_type=source_type,
        cowrie_session_id=accepted.session,
        event_type=accepted.event_type,
        occurred_at=accepted.timestamp,
        raw_text=text.raw,
        normalized_text=text.normalized,
        truncated=truncated,
        username=username,
        attempted_secret=attempted_secret,
        artifact_sha256=artifact_sha256,
        src_ip=src_ip,
        src_port=src_port,
    )
