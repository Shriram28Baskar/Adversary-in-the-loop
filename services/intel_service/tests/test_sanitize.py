"""FR-013 sanitization (ARCHITECTURE.md §10; ADR-024 D7)."""

from __future__ import annotations

import random
import unicodedata

import pytest

from intel_service.sanitize import (
    FIELD_LIMIT_BYTES,
    NORMALIZED_LIMIT_CHARS,
    RAW_LIMIT_BYTES,
    normalize,
    sanitize,
    sanitize_field,
)


def test_plain_text_is_unchanged() -> None:
    result = sanitize("uname -a")
    assert (result.raw, result.normalized, result.truncated) == ("uname -a", "uname -a", False)


@pytest.mark.parametrize(
    ("text", "normalized"),
    [
        ("\x1b[2J\x1b[31mred\x1b[0m", "red"),  # CSI
        ("\x9b31mred", "red"),  # C1 CSI
        ("\x1b]0;title\x07ls", "ls"),  # OSC ended by BEL
        ("\x1b]0;title\x1b\\ls", "ls"),  # OSC ended by ST
        ("\x1bPdcs-payload\x1b\\ls", "ls"),  # DCS
        ("\x1bcls", "ls"),  # two-character escape
        ("ls\x1b", "ls"),  # trailing ESC
        ("\x1b[31", ""),  # unterminated CSI swallows the rest
        ("a\x00b\x7fc\x08d", "abcd"),  # NUL, DEL, BS removed
        ("\x85x\x9fy", " xy"),  # C1: NEL is whitespace, others removed
        ("e\u0301", "\u00e9"),  # NFC
    ],
)
def test_normalized_form_removes_escapes_and_controls(text: str, normalized: str) -> None:
    assert normalize(text) == (normalized, False)


@pytest.mark.parametrize("separator", ["\t", "\n", "\r", "\x0b", "\x0c", "\u2028", "\u2029"])
def test_whitespace_controls_cannot_glue_tokens(separator: str) -> None:
    normalized, _ = normalize(f"cat{separator}~/.ssh/id_rsa")
    assert normalized.split() == ["cat", "~/.ssh/id_rsa"]


def test_raw_form_keeps_evidence_but_stays_storable() -> None:
    hostile = "\x1b[31m$(id)\x00\ud800../../etc/shadow"
    result = sanitize(hostile)
    assert result.raw == "\x1b[31m$(id)\ufffd\ufffd../../etc/shadow"  # escapes kept as evidence
    assert result.normalized == "$(id)\ufffd../../etc/shadow"  # NUL removed; surrogate replaced
    result.raw.encode("utf-8")  # always encodable
    assert "\x00" not in result.raw


def test_nothing_is_interpreted() -> None:
    for text in ("../../../../etc/passwd", "~/.ssh/id_rsa", "$HOME/x", "`id`", "a;b|c&&d"):
        assert sanitize(text).normalized == text


def test_bidi_and_format_characters_are_not_control_characters() -> None:
    """FR-013 removes control characters (Cc); format characters (Cf) stay as evidence."""
    assert normalize("\u202eevil\u202c") == ("\u202eevil\u202c", False)


def test_raw_is_capped_on_a_character_boundary() -> None:
    result = sanitize("\u00e9" * 3000)  # 6000 bytes
    assert len(result.raw.encode("utf-8")) <= RAW_LIMIT_BYTES
    assert result.raw == "\u00e9" * (RAW_LIMIT_BYTES // 2)
    assert result.truncated


def test_normalized_is_capped_and_flagged() -> None:
    result = sanitize("A" * 2000)
    assert result.raw == "A" * 2000
    assert result.normalized == "A" * NORMALIZED_LIMIT_CHARS
    assert result.truncated


def test_short_fields_are_capped_at_256_bytes() -> None:
    value, cut = sanitize_field("x" * 300)
    assert (len(value), cut) == (FIELD_LIMIT_BYTES, True)
    assert sanitize_field("root\x00") == ("root\ufffd", False)


def test_sanitization_properties_on_seeded_random_input() -> None:
    """Deterministic fuzz: every output is bounded, storable, control-free and stable."""
    rng = random.Random(4)  # noqa: S311 - deterministic test data, not crypto
    alphabet = "ab /.~-$`;|\x1b[]P\\\x07\x00\x7f\x85\x9b\x9c\t\n\r\u202e\u00e9e\u0301\ud800"
    for _ in range(2000):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 1500)))
        result = sanitize(text)
        assert len(result.raw.encode("utf-8")) <= RAW_LIMIT_BYTES
        assert len(result.normalized) <= NORMALIZED_LIMIT_CHARS
        assert "\x00" not in result.raw
        assert not any(unicodedata.category(ch) == "Cc" for ch in result.normalized)
        assert sanitize(text) == result  # pure
