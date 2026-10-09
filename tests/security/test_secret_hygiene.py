"""No secrets are committed (CLAUDE.md Git Rules; PRD SEC-003).

- Tracked files contain no credential material (private keys, provider/cloud
  tokens, inline password/secret/token assignments).
- The generated-secrets directory is git-ignored and nothing under it is tracked.
- ``deploy/secrets/generate.sh`` produces owner-only files of sufficient
  strength, keeps existing secrets, and only regenerates with ``--force``.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GENERATE = REPO_ROOT / "deploy" / "secrets" / "generate.sh"
THIS_FILE = Path(__file__).resolve()

SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "private key block": re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"),
    "anthropic key": re.compile(r"sk-ant-[A-Za-z0-9_\-]{16,}"),
    "openai-style key": re.compile(r"\bsk-[A-Za-z0-9]{32,}"),
    "aws access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"),
    "slack token": re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"),
    # `:` directly followed by a quoted identifier is a psql variable reference
    # (e.g. PASSWORD :'role_password'), not a literal value.
    "inline secret assignment": re.compile(
        r"(?i)\b(password|passwd|secret|api_?key|token)\b\s*"
        r"(?:=|:(?!'[a-z_][a-z0-9_]*'))\s*['\"][^'\"$\s{}<>]{12,}['\"]"
    ),
    # Literal values only; template placeholders ({x}, $x, %s) are not secrets.
    "SQL password literal": re.compile(r"(?i)\bPASSWORD\s+E?'[^'\s{}$%:]{8,}'"),
}


def _tracked_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"], capture_output=True, check=True, cwd=REPO_ROOT
    )
    return [REPO_ROOT / name for name in result.stdout.decode().split("\0") if name]


def _scan(text: str) -> list[str]:
    return [label for label, pattern in SECRET_PATTERNS.items() if pattern.search(text)]


def test_tracked_files_contain_no_secrets() -> None:
    findings: list[str] = []
    for path in _tracked_files():
        if path.resolve() == THIS_FILE or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        findings.extend(f"{path.relative_to(REPO_ROOT)}: {label}" for label in _scan(text))
    assert findings == []


@pytest.mark.parametrize(
    "sample",
    [
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "key = 'sk-ant-api03-abcdefghijklmnopqrstuvwx'",
        "AKIAABCDEFGHIJKLMNOP",
        "ghp_" + "a" * 36,
        'password = "correct-horse-battery"',
        "api_key: 'abcdefghijklmnopqrst'",
        "ALTER ROLE intel_svc PASSWORD 'correct-horse-battery';",
        "CREATE ROLE x LOGIN PASSWORD E'correct-horse-battery'",
        "password: 'correct-horse-battery'",
    ],
)
def test_scanner_detects_known_secret_shapes(sample: str) -> None:
    assert _scan(sample)


@pytest.mark.parametrize(
    "sample",
    [
        "POSTGRES_PASSWORD_FILE: /run/secrets/postgres_superuser_password",
        "password = os.environ['X']",
        'token = "${SERVICE_TOKEN}"',
        "the capability token is revoked at teardown",
        "ALTER ROLE intel_svc LOGIN PASSWORD :'intel_svc_password';",
        "f\"CREATE ROLE aitl_intruder LOGIN PASSWORD '{password}'\"",
    ],
)
def test_scanner_ignores_references_to_secrets(sample: str) -> None:
    assert _scan(sample) == []


def test_generated_secrets_directory_is_ignored_and_untracked() -> None:
    probe = "deploy/secrets/generated/postgres_superuser_password"
    ignored = subprocess.run(["git", "check-ignore", "-q", probe], cwd=REPO_ROOT, check=False)
    assert ignored.returncode == 0, "deploy/secrets/generated/ must be git-ignored"
    tracked = [p for p in _tracked_files() if "deploy/secrets/generated" in p.as_posix()]
    assert tracked == []


def _run_generate(workdir: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["sh", str(workdir / "generate.sh"), *args],
        capture_output=True,
        text=True,
        check=False,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
    )


@pytest.fixture
def generator(tmp_path: Path) -> Path:
    shutil.copy(GENERATE, tmp_path / "generate.sh")
    return tmp_path


def test_generate_creates_owner_only_strong_secrets(generator: Path) -> None:
    """The 0700 directory is the host access boundary.

    Non-swarm Compose bind-mounts file secrets with their host mode, and the
    consumers read them as non-root (postgres after gosu; db-migrate as 65534),
    so the files themselves are 0644 and never group/world-writable.
    """
    result = _run_generate(generator)
    assert result.returncode == 0, result.stderr
    out_dir = generator / "generated"
    assert stat.S_IMODE(out_dir.stat().st_mode) == 0o700
    secret = out_dir / "postgres_superuser_password"
    assert stat.S_IMODE(secret.stat().st_mode) == 0o644
    assert {p.name for p in out_dir.iterdir()} >= {"aitl_migrator_password"}
    value = secret.read_text().strip()
    assert len(value) >= 32
    assert re.fullmatch(r"[A-Za-z0-9_\-]+", value)


def test_generate_keeps_existing_and_force_regenerates(generator: Path) -> None:
    assert _run_generate(generator).returncode == 0
    secret = generator / "generated" / "postgres_superuser_password"
    first = secret.read_text()
    assert _run_generate(generator).returncode == 0
    assert secret.read_text() == first
    assert _run_generate(generator, "--force").returncode == 0
    assert secret.read_text() != first


def test_generate_rejects_unknown_arguments(generator: Path) -> None:
    result = _run_generate(generator, "--yolo")
    assert result.returncode == 2
    assert not (generator / "generated").exists()
