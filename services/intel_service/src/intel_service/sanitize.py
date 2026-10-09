"""FR-013 sanitization of attacker-derived text (ARCHITECTURE.md §10; ADR-024 D7).

Every attacker-derived field is stored twice, both as ``untrusted_text``:

- **raw**: the text as received, capped at 4096 UTF-8 bytes (cut on a
  character boundary; truncation flagged). Two code points PostgreSQL text
  and UTF-8 cannot store - U+0000 and lone surrogates (possible via JSON
  ``\\u`` escapes) - are replaced with U+FFFD, the same treatment FR-013
  prescribes for invalid UTF-8.
- **normalized**: Unicode NFC; terminal escape sequences (ESC/CSI/OSC/DCS
  strings) removed; whitespace control characters (TAB, LF, VT, FF, CR, and
  their C1/Unicode separators) turned into a space so that removing them can
  never glue two tokens together; every other control character (Unicode
  category Cc) removed; capped at 1024 characters.

Classification reads only the normalized form (FR-006/FR-007). Nothing here
interprets the text: no shell parsing, no path resolution, no expansion.
The escape scanner is a linear state machine (no regular expressions).
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from typing import Final

__all__ = [
    "FIELD_LIMIT_BYTES",
    "NORMALIZED_LIMIT_CHARS",
    "RAW_LIMIT_BYTES",
    "Sanitized",
    "cap_bytes",
    "normalize",
    "sanitize",
    "sanitize_field",
    "storable",
]

RAW_LIMIT_BYTES: Final = 4096
NORMALIZED_LIMIT_CHARS: Final = 1024
FIELD_LIMIT_BYTES: Final = 256  # username / attempted_secret columns
REPLACEMENT: Final = "\ufffd"
_ESC: Final = "\x1b"
_CSI_C1: Final = "\x9b"
_OSC_C1: Final = "\x9d"
_BEL: Final = "\x07"
_ST_C1: Final = "\x9c"
_STRING_INTRODUCERS: Final = frozenset("]PX^_")  # OSC, DCS, SOS, PM, APC
_WHITESPACE_CONTROLS: Final = frozenset("\t\n\x0b\x0c\r\x1c\x1d\x1e\x1f\x85\u2028\u2029")


@dataclass(frozen=True, slots=True)
class Sanitized:
    raw: str
    normalized: str
    truncated: bool


def _replace_surrogates(text: str) -> str:
    """Lone surrogates are invalid UTF-8: replace them (FR-013)."""
    if text.isascii():
        return text
    return "".join(REPLACEMENT if 0xD800 <= ord(ch) <= 0xDFFF else ch for ch in text)


def storable(text: str) -> str:
    """Replace the code points PostgreSQL text/UTF-8 cannot hold with U+FFFD."""
    return _replace_surrogates(text).replace("\x00", REPLACEMENT)


def cap_bytes(text: str, limit: int) -> tuple[str, bool]:
    """Cut ``text`` to at most ``limit`` UTF-8 bytes on a character boundary."""
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text, False
    return encoded[:limit].decode("utf-8", errors="ignore"), True


def _strip_escapes(text: str) -> str:
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if (ch == _ESC and i + 1 < n and text[i + 1] == "[") or ch == _CSI_C1:
            # CSI: parameters and intermediates up to a final byte 0x40-0x7E.
            i += 2 if ch == _ESC else 1
            while i < n and not "\x40" <= text[i] <= "\x7e":
                i += 1
            i += 1
        elif (ch == _ESC and i + 1 < n and text[i + 1] in _STRING_INTRODUCERS) or ch == _OSC_C1:
            # String sequences end at BEL, ST (ESC \) or C1 ST.
            i += 2 if ch == _ESC else 1
            while i < n:
                if text[i] in (_BEL, _ST_C1):
                    i += 1
                    break
                if text[i] == _ESC and i + 1 < n and text[i + 1] == "\\":
                    i += 2
                    break
                i += 1
        elif ch == _ESC:
            i += 2  # two-character escape (ESC c, ESC 7, ...), or a trailing ESC
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def normalize(text: str) -> tuple[str, bool]:
    """The normalized form and whether it was capped."""
    stripped = _strip_escapes(unicodedata.normalize("NFC", _replace_surrogates(text)))
    cleaned = "".join(
        " " if ch in _WHITESPACE_CONTROLS else ch
        for ch in stripped
        if ch in _WHITESPACE_CONTROLS or unicodedata.category(ch) != "Cc"
    )
    if len(cleaned) > NORMALIZED_LIMIT_CHARS:
        return cleaned[:NORMALIZED_LIMIT_CHARS], True
    return cleaned, False


def sanitize(text: str) -> Sanitized:
    """Raw and normalized forms of one attacker-derived text field (FR-013)."""
    raw, raw_cut = cap_bytes(storable(text), RAW_LIMIT_BYTES)
    normalized, normalized_cut = normalize(text)
    return Sanitized(raw=raw, normalized=normalized, truncated=raw_cut or normalized_cut)


def sanitize_field(text: str) -> tuple[str, bool]:
    """A dedicated short field (username, attempted secret): storable, 256 bytes."""
    return cap_bytes(storable(text), FIELD_LIMIT_BYTES)
