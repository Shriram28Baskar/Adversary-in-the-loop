"""Canonical JSON serialization and SHA-256 hashing.

Every content hash in the platform (configuration artifacts, locked execution
configurations, trajectory seals, taint snapshots) is computed over the bytes
produced here, so two semantically equal values must always serialize to the
same bytes (PRD FR-031, FR-027; ARCHITECTURE.md §21).

Canonical form:
- UTF-8 bytes, no insignificant whitespace (``,`` and ``:`` separators).
- Object keys must be ``str`` and are sorted by Unicode code point.
- Supported values: ``None``, ``bool``, ``int``, finite ``float``, finite
  ``decimal.Decimal`` (serialized as a JSON string of ``str(value)``), ``str``,
  ``list``/``tuple`` (serialized as arrays), and ``dict`` with ``str`` keys.
- NaN and infinities (float or Decimal) are rejected, as are unsupported types,
  non-string keys, and strings that cannot be encoded as UTF-8 (lone surrogates).
- Non-ASCII characters are emitted as raw UTF-8, not ``\\u`` escapes; control
  characters use the standard JSON escapes.
"""

from __future__ import annotations

import hashlib
import json
import math
from decimal import Decimal
from typing import Any

__all__ = ["CanonicalJSONError", "canonical_sha256", "dumps", "sha256_hex"]


class CanonicalJSONError(ValueError):
    """Raised when a value cannot be represented in canonical JSON."""


def _normalize(value: Any, path: str) -> Any:
    # bool must be checked before int (bool is a subclass of int).
    if value is None or isinstance(value, bool | str):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalJSONError(f"non-finite float at {path}")
        return value
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise CanonicalJSONError(f"non-finite Decimal at {path}")
        return str(value)
    if isinstance(value, list | tuple):
        return [_normalize(item, f"{path}[{index}]") for index, item in enumerate(value)]
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalJSONError(f"non-string key {key!r} at {path}")
            normalized[key] = _normalize(item, f"{path}.{key}")
        return normalized
    raise CanonicalJSONError(f"unsupported type {type(value).__name__} at {path}")


def dumps(obj: Any) -> bytes:
    """Serialize ``obj`` to canonical JSON bytes."""
    normalized = _normalize(obj, "$")
    text = json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CanonicalJSONError("string is not encodable as UTF-8") from exc


def sha256_hex(data: bytes) -> str:
    """Return the lowercase hex SHA-256 digest of ``data``."""
    if not isinstance(data, bytes | bytearray | memoryview):
        raise TypeError("sha256_hex requires bytes")
    return hashlib.sha256(data).hexdigest()


def canonical_sha256(obj: Any) -> str:
    """Return the SHA-256 hex digest of the canonical JSON form of ``obj``."""
    return sha256_hex(dumps(obj))
