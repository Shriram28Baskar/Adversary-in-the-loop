"""Structured JSON logging with correlation IDs (PRD NFR-008, SEC-009).

Every log line is one JSON object. Safety properties:

- **No log injection.** Lines are produced by ``json.dumps(..., ensure_ascii=True)``,
  so newlines, carriage returns, terminal escape sequences, and any other
  control or non-ASCII characters in field values are escaped. Attacker-derived
  strings can never start a new log line or emit raw escape bytes.
- **No attacker-controlled formatting.** ``log_event`` takes a constant event
  name (validated against a fixed pattern) and keyword fields; field values are
  data, never format strings. Records from third-party loggers are formatted
  defensively (a formatting failure is reported, not raised).
- **No credential leakage.** Field names that denote credentials (password,
  secret, token, api key, authorization, cookie, credential, private key) are
  redacted recursively, as are string values carrying a ``Bearer`` credential.

Correlation IDs (``correlation_id``, ``execution_id``, ``pair_id``) are held in
context variables and attached to every record emitted inside a
``correlation_scope``. They must be UUIDs; anything else is rejected.
"""

from __future__ import annotations

import contextlib
import contextvars
import json
import logging
import re
import sys
import traceback
import uuid
from collections.abc import Iterator, Mapping
from datetime import UTC, datetime
from typing import Any, TextIO

__all__ = [
    "CYCLE",
    "MAX_DEPTH",
    "REDACTED",
    "TOO_DEEP",
    "JsonFormatter",
    "configure_logging",
    "correlation_scope",
    "current_correlation",
    "log_event",
    "new_correlation_id",
    "parse_correlation_id",
    "redact",
]

REDACTED = "[REDACTED]"
CYCLE = "[CYCLE]"
TOO_DEEP = "[TOO_DEEP]"
MAX_DEPTH = 32

_EVENT_NAME = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$")
_SECRET_KEY_SEGMENTS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "apikey",
        "authorization",
        "cookie",
        "credential",
        "credentials",
    }
)
_SECRET_KEY_SUBSTRINGS = ("api_key", "api-key", "private_key", "private-key")
_BEARER = re.compile(r"^\s*bearer\s+\S", re.IGNORECASE)

_correlation_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "aitl_correlation_id", default=None
)
_execution_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "aitl_execution_id", default=None
)
_pair_id: contextvars.ContextVar[str | None] = contextvars.ContextVar("aitl_pair_id", default=None)


def _is_secret_key(key: str) -> bool:
    lowered = key.lower()
    if any(fragment in lowered for fragment in _SECRET_KEY_SUBSTRINGS):
        return True
    return any(segment in _SECRET_KEY_SEGMENTS for segment in re.split(r"[_\-.\s]+", lowered))


def redact(value: Any) -> Any:
    """Return a copy of ``value`` with credential-bearing keys and values redacted.

    Cycles are replaced by ``CYCLE`` and nesting deeper than ``MAX_DEPTH`` by
    ``TOO_DEEP``, so hostile or accidental structures cannot exhaust the stack.
    """
    return _redact(value, depth=0, active=set())


def _redact(value: Any, *, depth: int, active: set[int]) -> Any:
    if isinstance(value, Mapping | list | tuple):
        if id(value) in active:
            return CYCLE
        if depth >= MAX_DEPTH:
            return TOO_DEEP
        active.add(id(value))
        try:
            if isinstance(value, Mapping):
                return {
                    str(key): (
                        REDACTED
                        if _is_secret_key(str(key))
                        else _redact(item, depth=depth + 1, active=active)
                    )
                    for key, item in value.items()
                }
            return [_redact(item, depth=depth + 1, active=active) for item in value]
        finally:
            active.discard(id(value))
    if isinstance(value, str) and _BEARER.match(value):
        return REDACTED
    return value


def _require_uuid(name: str, value: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError, TypeError) as exc:
        raise ValueError(f"{name} must be a UUID") from exc
    canonical = str(parsed)
    if canonical != value.lower():
        raise ValueError(f"{name} must be a canonical hyphenated UUID")
    return canonical


def new_correlation_id() -> str:
    """Return a fresh correlation ID."""
    return str(uuid.uuid4())


def parse_correlation_id(header_value: str | None) -> str:
    """Accept a caller-supplied correlation ID only if it is a canonical UUID.

    Anything else (missing, malformed, oversized, or injected content) is
    replaced by a fresh ID rather than propagated into logs.
    """
    if header_value is not None and len(header_value) == 36:
        with contextlib.suppress(ValueError):
            return _require_uuid("correlation_id", header_value)
    return new_correlation_id()


@contextlib.contextmanager
def correlation_scope(
    *,
    correlation_id: str | None = None,
    execution_id: str | None = None,
    pair_id: str | None = None,
) -> Iterator[str]:
    """Bind correlation IDs for the duration of the block; yields the correlation ID."""
    cid = (
        _require_uuid("correlation_id", correlation_id)
        if correlation_id
        else (_correlation_id.get() or new_correlation_id())
    )
    tokens = [_correlation_id.set(cid)]
    if execution_id is not None:
        tokens.append(_execution_id.set(_require_uuid("execution_id", execution_id)))
    if pair_id is not None:
        tokens.append(_pair_id.set(_require_uuid("pair_id", pair_id)))
    try:
        yield cid
    finally:
        for token in reversed(tokens):
            token.var.reset(token)


def current_correlation() -> dict[str, str]:
    """Return the correlation IDs bound in the current context."""
    bound = {
        "correlation_id": _correlation_id.get(),
        "execution_id": _execution_id.get(),
        "pair_id": _pair_id.get(),
    }
    return {key: value for key, value in bound.items() if value is not None}


def _json_default(value: Any) -> str:
    try:
        return str(value)
    except Exception:  # noqa: BLE001 - an unprintable object must never break logging
        return f"<unserializable {type(value).__name__}>"


class JsonFormatter(logging.Formatter):
    """Render each record as a single-line, ASCII-only JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
        }
        event = getattr(record, "aitl_event", None)
        if isinstance(event, str):
            payload["event"] = event
            fields = getattr(record, "aitl_fields", None)
            if isinstance(fields, Mapping) and fields:
                payload["fields"] = redact(fields)
        else:
            try:
                message = record.getMessage()
            except Exception:  # noqa: BLE001 - malformed %-format from a third-party caller
                message = f"<unformattable message: {record.msg!r}>"
            payload["message"] = redact(message)
        payload.update(getattr(record, "aitl_correlation", None) or current_correlation())
        if record.exc_info and record.exc_info[0] is not None:
            payload["exc_type"] = record.exc_info[0].__name__
            payload["exc"] = "".join(traceback.format_exception(*record.exc_info))
        try:
            return json.dumps(
                payload, ensure_ascii=True, allow_nan=False, default=_json_default, sort_keys=True
            )
        except ValueError:  # e.g. NaN/Infinity in fields: keep every line strict JSON
            payload.pop("fields", None)
            payload["log_error"] = "fields not serializable"
            return json.dumps(payload, ensure_ascii=True, default=_json_default, sort_keys=True)


def log_event(logger: logging.Logger, level: int, event: str, /, **fields: Any) -> None:
    """Emit a structured event.

    ``event`` is a constant dotted identifier such as ``service_auth.rejected``;
    all variable data goes in ``fields`` so it is JSON-encoded, never formatted.
    """
    if not _EVENT_NAME.fullmatch(event):
        raise ValueError(f"invalid event name {event!r}")
    logger.log(
        level,
        event,
        extra={
            "aitl_event": event,
            "aitl_fields": fields,
            "aitl_correlation": current_correlation(),
        },
    )


def configure_logging(level: int = logging.INFO, stream: TextIO | None = None) -> None:
    """Install the JSON formatter as the only root handler."""
    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
