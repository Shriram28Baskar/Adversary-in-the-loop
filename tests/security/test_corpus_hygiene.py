"""The synthetic corpus and the repository carry no attacker samples (P3; FR-005b, SEC-003).

- Every IPv4 address in the corpus is in an RFC 5737 documentation range (or
  a deliberately invalid address used by a malformed-line case), so no real
  host is named.
- The one ``file_download`` event records the digest of an inert placeholder
  string; no downloaded or uploaded payload exists anywhere in the repository.
- No tracked file is an executable binary or script sample (ELF/PE/Mach-O
  magic, or a corpus file with a shebang or the executable bit).
"""

from __future__ import annotations

import ipaddress
import json
import re
import stat
import subprocess
from pathlib import Path

from tests.fixtures import honeypot_corpus

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCUMENTATION = [
    ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
]
INVALID_ON_PURPOSE = {"999.1.1.1"}
BINARY_MAGIC = (b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe")


def _corpus_files() -> list[Path]:
    return sorted(honeypot_corpus.CORPUS_DIR.iterdir())


def test_corpus_names_only_documentation_addresses() -> None:
    for path in _corpus_files():
        text = path.read_bytes().decode("utf-8", errors="replace")
        for candidate in set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)):
            if candidate in INVALID_ON_PURPOSE:
                continue
            address = ipaddress.ip_address(candidate)
            assert any(address in net for net in DOCUMENTATION), (path.name, candidate)


def test_corpus_download_records_only_a_placeholder_digest() -> None:
    downloads = []
    for path in _corpus_files():
        for line in path.read_bytes().splitlines():
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if isinstance(event, dict) and str(event.get("eventid", "")).startswith(
                ("cowrie.session.file_download", "cowrie.session.file_upload")
            ):
                downloads.append(event)
    assert downloads
    assert {d["shasum"] for d in downloads} == {honeypot_corpus.PLACEHOLDER_SHA256}


def test_corpus_files_are_not_executable_or_scripts() -> None:
    for path in _corpus_files():
        assert not path.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH), path
        head = path.read_bytes()[:4]
        assert not head.startswith(b"#!"), path
        assert not head.startswith(BINARY_MAGIC), path


def test_no_tracked_file_is_an_executable_binary() -> None:
    tracked = subprocess.run(
        ["git", "ls-files", "-z"], capture_output=True, check=True, cwd=REPO_ROOT
    ).stdout.split(b"\0")
    for name in filter(None, tracked):
        path = REPO_ROOT / name.decode()
        if path.is_file():
            with open(path, "rb") as handle:
                head = handle.read(4)
            assert not head.startswith(BINARY_MAGIC), name
