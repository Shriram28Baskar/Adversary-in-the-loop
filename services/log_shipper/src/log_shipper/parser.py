"""Strict, bounded parser for Cowrie JSON log lines (PRD FR-005, FR-013, FR-048).

Every line is hostile input. ``parse_line`` either accepts a line - returning
the exact text to stage and its hash - or rejects it with a quarantine stage
and a fixed reason code. It never executes, evaluates or interprets content,
and it never raises: an unexpected internal error is itself a rejection.

What "accepted" means (and does not mean): the line is a single, well-formed,
unambiguous JSON object of an allowlisted Cowrie event type, whose structural
fields (event ID, session ID, timestamp, addresses, ports, hashes) are valid
and whose attacker-controlled fields have the expected types and bounds. The
attacker text itself stays untrusted data. Per-field FR-013 normalization
(raw_text cap, NFC, control/escape stripping, normalized_text) is applied when
intel-service promotes the staged line into AttackEvent (ARCHITECTURE.md §10);
P3 stages the validated line verbatim so no evidence is lost or rewritten.

Encoding (FR-013): invalid UTF-8 sequences are replaced (U+FFFD), not
rejected. A line must contain no raw control bytes: Cowrie writes compact,
ASCII-escaped JSON (``json.dumps`` defaults), so a raw control byte means the
line did not come from Cowrie intact.
"""

from __future__ import annotations

import ipaddress
import json
import math
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from typing import Any, Final, Literal

from aitl_common.canonical_json import sha256_hex

__all__ = [
    "EVENTS",
    "MAX_LINE_BYTES",
    "Accepted",
    "Rejected",
    "parse_line",
]

# Staged payloads are untrusted_text (<= 65536 bytes, migration 0001).
MAX_LINE_BYTES: Final = 65536
MAX_KEYS: Final = 64
MAX_DEPTH: Final = 4
MAX_LIST_ITEMS: Final = 128
MAX_INT_DIGITS: Final = 19
EARLIEST: Final = datetime(2000, 1, 1, tzinfo=UTC)
LATEST: Final = datetime(2100, 1, 1, tzinfo=UTC)

_SESSION = re.compile(r"[0-9a-f]{8,32}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_KEY = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_NUMBER_TEXT = re.compile(r"[0-9]{1,9}(?:\.[0-9]{1,6})?")
_TIMESTAMP = re.compile(
    r"(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})T(?P<time>[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.(?P<frac>[0-9]{1,6}))?(?P<zone>Z|[+-][0-9]{2}:?[0-9]{2})"
)

Stage = Literal["shipper_parse", "shipper_validate"]


@dataclass(frozen=True, slots=True)
class Accepted:
    payload: str  # the validated line, verbatim (UTF-8 invalid sequences replaced)
    payload_sha256: str
    eventid: str
    event_type: str
    session: str
    timestamp: datetime  # UTC


@dataclass(frozen=True, slots=True)
class Rejected:
    stage: Stage
    reason: str  # fixed code, never derived from content
    line: bytes  # the raw line, for a bounded, escaped quarantine preview


# --- field types ------------------------------------------------------------------------

Check = Callable[[Any], bool]


def _is_str(value: Any) -> bool:
    return isinstance(value, str)


def _is_ip(value: Any) -> bool:
    if not isinstance(value, str) or len(value) > 45:
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _is_port(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 65535


def _is_small_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 100_000


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _is_duration(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int | float):
        return math.isfinite(value) and 0 <= value <= 10**9
    return isinstance(value, str) and _NUMBER_TEXT.fullmatch(value) is not None


def _is_protocol(value: Any) -> bool:
    return value in ("ssh", "telnet")


@dataclass(frozen=True, slots=True)
class Field:
    check: Check
    required: bool = True


@dataclass(frozen=True, slots=True)
class EventSpec:
    event_type: str  # the event_type enum label the event maps to (migration 0001)
    fields: Mapping[str, Field]


def _spec(event_type: str, **fields: Field) -> EventSpec:
    return EventSpec(event_type, fields)


STR = Field(_is_str)
IP = Field(_is_ip)
PORT = Field(_is_port)

# Cowrie 3.0.15 event IDs accepted into staging. Anything else is quarantined
# (FR-048). Mapping to the event_type enum is format mapping only, not intent.
EVENTS: Final[Mapping[str, EventSpec]] = {
    "cowrie.session.connect": _spec(
        "session_connect",
        src_ip=IP,
        src_port=PORT,
        dst_ip=IP,
        dst_port=PORT,
        protocol=Field(_is_protocol, required=False),
    ),
    "cowrie.client.version": _spec("client_version", version=STR),
    "cowrie.client.kex": _spec("other", hassh=Field(_is_str, required=False)),
    "cowrie.client.size": _spec("other", width=Field(_is_small_int), height=Field(_is_small_int)),
    "cowrie.client.var": _spec("other", name=STR, value=STR),
    "cowrie.client.fingerprint": _spec("other"),
    "cowrie.session.params": _spec("other"),
    "cowrie.login.failed": _spec("login_failed", username=STR, password=STR),
    "cowrie.login.success": _spec("login_success", username=STR, password=STR),
    "cowrie.command.input": _spec("command_input", input=STR),
    "cowrie.command.failed": _spec("other", input=STR),
    "cowrie.command.success": _spec("other", input=STR),
    "cowrie.session.file_download": _spec(
        "file_download",
        url=STR,
        shasum=Field(_is_sha256),
        outfile=Field(_is_str, required=False),
    ),
    "cowrie.session.file_download.failed": _spec("other", url=Field(_is_str, required=False)),
    "cowrie.session.file_upload": _spec(
        "file_upload",
        filename=STR,
        shasum=Field(_is_sha256),
        outfile=Field(_is_str, required=False),
    ),
    "cowrie.direct-tcpip.request": _spec("other", dst_ip=STR, dst_port=PORT),
    "cowrie.direct-tcpip.data": _spec("other"),
    "cowrie.log.closed": _spec("other"),
    "cowrie.session.closed": _spec("session_closed", duration=Field(_is_duration, required=False)),
}


# --- strict JSON ----------------------------------------------------------------------


class _InvalidLineError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    if len(pairs) > MAX_KEYS:
        raise _InvalidLineError("json.too_many_keys")
    result: dict[str, Any] = {}
    folded: set[str] = set()
    for key, value in pairs:
        if key in result:
            raise _InvalidLineError("json.duplicate_key")
        if _KEY.fullmatch(key) is None:
            raise _InvalidLineError("json.invalid_key")
        if key.lower() in folded:
            raise _InvalidLineError("json.ambiguous_key")
        folded.add(key.lower())
        result[key] = value
    return result


def _constant(name: str) -> Any:
    raise _InvalidLineError("json.non_finite_number")


def _integer(text: str) -> int:
    if len(text.lstrip("-")) > MAX_INT_DIGITS:
        raise _InvalidLineError("json.number_out_of_range")
    return int(text)


def _float(text: str) -> float:
    if len(text) > 32:
        raise _InvalidLineError("json.number_out_of_range")
    value = float(text)
    if not math.isfinite(value):
        raise _InvalidLineError("json.non_finite_number")
    return value


def _check_shape(value: Any, depth: int) -> None:
    if depth > MAX_DEPTH:
        raise _InvalidLineError("json.too_deep")
    if isinstance(value, dict):
        for item in value.values():
            _check_shape(item, depth + 1)
    elif isinstance(value, list):
        if len(value) > MAX_LIST_ITEMS:
            raise _InvalidLineError("json.list_too_long")
        for item in value:
            _check_shape(item, depth + 1)


def _parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise _InvalidLineError("event.invalid_timestamp")
    match = _TIMESTAMP.fullmatch(value)
    if match is None:
        raise _InvalidLineError("event.invalid_timestamp")
    zone = match["zone"]
    offset = timedelta(0)
    if zone != "Z":
        digits = zone[1:].replace(":", "")
        hours, minutes = int(digits[:2]), int(digits[2:])
        if hours > 14 or minutes > 59:
            raise _InvalidLineError("event.invalid_timestamp")
        offset = timedelta(hours=hours, minutes=minutes) * (1 if zone[0] == "+" else -1)
    try:
        parsed = datetime.fromisoformat(f"{match['date']}T{match['time']}").replace(
            microsecond=int((match["frac"] or "0").ljust(6, "0")),
            tzinfo=timezone(offset),
        )
    except ValueError:
        raise _InvalidLineError("event.invalid_timestamp") from None
    parsed = parsed.astimezone(UTC)
    if not EARLIEST <= parsed < LATEST:
        raise _InvalidLineError("event.timestamp_out_of_range")
    return parsed


# --- entry point -------------------------------------------------------------------------


def parse_line(line: bytes) -> Accepted | Rejected:
    """Validate one line (without its trailing newline). Never raises."""
    try:
        return _parse(line)
    except _InvalidLineError as invalid:
        stage: Stage = (
            "shipper_parse"
            if invalid.reason.startswith(("line.", "json."))
            else ("shipper_validate")
        )
        return Rejected(stage, invalid.reason, line)
    except Exception:  # noqa: BLE001 - never fall back to interpreting the line
        return Rejected("shipper_parse", "parser.internal_error", line)


def _parse(line: bytes) -> Accepted:
    if not line:
        raise _InvalidLineError("line.empty")
    if len(line) > MAX_LINE_BYTES:
        raise _InvalidLineError("line.too_long")
    if line.startswith(b"\xef\xbb\xbf"):
        raise _InvalidLineError("line.byte_order_mark")
    if any(byte < 0x20 or byte == 0x7F for byte in line):
        raise _InvalidLineError("line.control_bytes")
    text = line.decode("utf-8", errors="replace")
    if len(text.encode("utf-8")) > MAX_LINE_BYTES:
        raise _InvalidLineError("line.too_long")
    try:
        data = json.loads(
            text,
            object_pairs_hook=_object,
            parse_constant=_constant,
            parse_int=_integer,
            parse_float=_float,
        )
    except _InvalidLineError:
        raise
    except (ValueError, RecursionError):
        raise _InvalidLineError("json.invalid") from None
    if not isinstance(data, dict):
        raise _InvalidLineError("json.not_an_object")
    _check_shape(data, 1)

    eventid = data.get("eventid")
    if not isinstance(eventid, str):
        raise _InvalidLineError("event.missing_eventid")
    spec = EVENTS.get(eventid)
    if spec is None:
        raise _InvalidLineError("event.unknown_eventid")
    session = data.get("session")
    if not isinstance(session, str) or _SESSION.fullmatch(session) is None:
        raise _InvalidLineError("event.invalid_session")
    timestamp = _parse_timestamp(data.get("timestamp"))
    if "src_ip" in data and not _is_ip(data["src_ip"]):
        raise _InvalidLineError("event.invalid_src_ip")
    for name, field in spec.fields.items():
        if name not in data:
            if field.required:
                raise _InvalidLineError(f"event.missing_field.{name}")
            continue
        if not field.check(data[name]):
            raise _InvalidLineError(f"event.invalid_field.{name}")
    return Accepted(
        payload=text,
        payload_sha256=sha256_hex(text.encode("utf-8")),
        eventid=eventid,
        event_type=spec.event_type,
        session=session,
        timestamp=timestamp,
    )
