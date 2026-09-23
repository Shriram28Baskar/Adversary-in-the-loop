"""Cowrie hardening configuration (PRD FR-004a acceptance; ARCHITECTURE.md §9; plan HP-1).

The real overlay is checked against the pinned release's defaults, then each
rule is shown to catch a deliberate regression.
"""

from __future__ import annotations

import hashlib

import pytest

from tests.security import cowrie_policy
from tests.security.cowrie_policy import DIST, OVERLAY, USERDB

DIST_TEXT = DIST.read_text(encoding="utf-8")
OVERLAY_TEXT = OVERLAY.read_text(encoding="utf-8")


def test_vendored_defaults_are_the_pinned_release() -> None:
    assert hashlib.sha256(DIST.read_bytes()).hexdigest() == cowrie_policy.DIST_SHA256


def test_real_overlay_is_compliant() -> None:
    assert cowrie_policy.check(DIST_TEXT, OVERLAY_TEXT) == []


def test_defaults_alone_are_not_compliant() -> None:
    """Without the overlay, Cowrie 3.0.15 enables SSH forwarding by default."""
    violations = cowrie_policy.check(DIST_TEXT, "")
    assert any("[ssh] forwarding = 'true'" in v for v in violations)


def test_real_userdb_is_simple() -> None:
    assert cowrie_policy.check_userdb(USERDB.read_text(encoding="utf-8")) == []


def _replace(old: str, new: str) -> str:
    assert old in OVERLAY_TEXT, old
    return OVERLAY_TEXT.replace(old, new, 1)


@pytest.mark.parametrize(
    ("mutated", "fragment"),
    [
        (_replace("forwarding = false", "forwarding = true"), "[ssh] forwarding"),
        (_replace("forward_redirect = false", "forward_redirect = true"), "forward_redirect"),
        (_replace("forward_tunnel = false", "forward_tunnel = true"), "forward_tunnel"),
        # A typo is ignored by Cowrie and would silently keep forwarding enabled.
        (_replace("forwarding = false", "fowarding = false"), "fowarding is not an option"),
        (_replace("[telnet]\nenabled = false", "[telnet]\nenabled = true"), "[telnet] enabled"),
        (_replace("backend = shell", "backend = proxy"), "[honeypot] backend"),
        (_replace("backend = shell", "backend = llm"), "[honeypot] backend"),
        (_replace("out_addr = 127.0.0.1", "out_addr = 0.0.0.0"), "[honeypot] out_addr"),
        (_replace("out_addr = 127.0.0.1\n", ""), "out_addr must be set explicitly"),
        (
            _replace("download_limit_size = 1", "download_limit_size = 0"),
            "download_limit_size",
        ),
        (
            _replace("[output_virustotal]\nenabled = false", "[output_virustotal]\nenabled = true"),
            "[output_virustotal] must stay disabled",
        ),
        (
            _replace("[output_postgresql]\nenabled = false", "[output_postgresql]\nenabled = yes"),
            "[output_postgresql] must stay disabled",
        ),
        (
            _replace("[output_socketlog]\nenabled = false\n", ""),
            "[output_socketlog] enabled must be set explicitly",
        ),
        (_replace("ttylog = false", "ttylog = true"), "[honeypot] ttylog"),
        (OVERLAY_TEXT + "\n[output_webhook]\nenabled = false\n", "[output_webhook] is not"),
        (OVERLAY_TEXT + "\n[ssh]\nforwarding = true\n", "does not parse strictly"),
    ],
)
def test_detects_hardening_regression(mutated: str, fragment: str) -> None:
    violations = cowrie_policy.check(DIST_TEXT, mutated)
    assert any(fragment in v for v in violations), violations


@pytest.mark.parametrize(
    "line", ["root:x:$(id)", "root:x:pa ss", "root:x:`id`", "root;x:*", "../../x:x:*"]
)
def test_userdb_rejects_non_simple_entries(line: str) -> None:
    assert cowrie_policy.check_userdb(line)
