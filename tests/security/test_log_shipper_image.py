"""Log Shipper image and code surface (ARCHITECTURE.md §9; PRD FR-004b, FR-005, SEC-003).

- The image is digest-pinned, installs only hash-locked dependencies exported
  from uv.lock, runs unprivileged, and exposes no port.
- The shipper's code opens no listener and has no dynamic-execution path:
  no socket/server modules, no subprocess, no eval/exec/compile, no dynamic
  imports, no deserialization beyond ``json``. The only network client is the
  role-bound SQLAlchemy engine from aitl_common.
"""

from __future__ import annotations

import ast
import re
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SHIPPER = REPO_ROOT / "services" / "log_shipper"
DOCKERFILE = SHIPPER / "Dockerfile"
REQUIREMENTS = SHIPPER / "requirements.txt"
SOURCE = SHIPPER / "src" / "log_shipper"

FORBIDDEN_MODULES = frozenset(
    {
        "socket",
        "socketserver",
        "http",
        "urllib",
        "ssl",
        "asyncio",
        "selectors",
        "subprocess",
        "multiprocessing",
        "importlib",
        "pickle",
        "marshal",
        "shelve",
        "ctypes",
        "fastapi",
        "starlette",
        "uvicorn",
        "yaml",
        "requests",
        "httpx",
    }
)
FORBIDDEN_BUILTINS = frozenset({"eval", "exec", "compile", "__import__", "breakpoint"})
FORBIDDEN_METHODS = frozenset({"system", "popen", "execv", "execve", "spawnv", "fork"})


def test_image_is_pinned_hash_locked_unprivileged_and_portless() -> None:
    dockerfile = DOCKERFILE.read_text()
    froms = re.findall(r"^FROM\s+(\S+)", dockerfile, re.MULTILINE)
    assert len(froms) == 1
    assert re.search(r"@sha256:[0-9a-f]{64}$", froms[0]), froms
    assert "--require-hashes" in dockerfile
    assert "--only-binary=:all:" in dockerfile
    assert re.search(r"^USER 65534:65534$", dockerfile, re.MULTILINE)
    assert not re.search(r"^\s*EXPOSE\b", dockerfile, re.MULTILINE | re.IGNORECASE)
    assert re.findall(r"^COPY\s+(\S+)", dockerfile, re.MULTILINE) == [
        "services/log_shipper/requirements.txt",
        "packages/aitl_common/src/aitl_common",
        "services/log_shipper/src/log_shipper",
    ]
    assert re.search(r'^ENTRYPOINT \["python", "-m", "log_shipper"\]$', dockerfile, re.MULTILINE)


def test_requirements_match_lockfile() -> None:
    exported = subprocess.run(
        [
            "uv",
            "export",
            "--locked",
            "--package",
            "aitl-log-shipper",
            "--no-dev",
            "--no-emit-workspace",
            "--format",
            "requirements.txt",
            "--no-header",
        ],
        capture_output=True,
        text=True,
        check=True,
        cwd=REPO_ROOT,
    ).stdout

    def body(text: str) -> str:
        return "\n".join(line for line in text.splitlines() if not line.startswith("#")).strip()

    committed = REQUIREMENTS.read_text()
    assert body(committed) == body(exported)
    assert "--hash=sha256:" in committed


def _python_files() -> list[Path]:
    return sorted(SOURCE.rglob("*.py"))


def _violations(tree: ast.AST) -> list[str]:
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or ""]
        else:
            names = []
        for name in names:
            if name.split(".")[0] in FORBIDDEN_MODULES:
                found.append(f"import {name}")
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in FORBIDDEN_BUILTINS:
                found.append(f"call {func.id}")
            if isinstance(func, ast.Attribute) and func.attr in FORBIDDEN_METHODS:
                found.append(f"call .{func.attr}")
    return found


def test_source_is_scanned() -> None:
    names = {p.name for p in _python_files()}
    assert {"parser.py", "reader.py", "writer.py", "service.py", "__main__.py"} <= names


@pytest.mark.parametrize("path", _python_files(), ids=lambda p: p.name)
def test_shipper_opens_no_listener_and_executes_nothing(path: Path) -> None:
    assert _violations(ast.parse(path.read_text(), filename=str(path))) == []


@pytest.mark.parametrize(
    "snippet",
    [
        "import socket",
        "from http.server import HTTPServer",
        "import asyncio\nasyncio.start_server(None)",
        "from fastapi import FastAPI",
        "import subprocess",
        "eval(line)",
        "exec(line)",
        "import importlib",
        "os.system(line)",
        "compile(src, 'x', 'exec')",
        "os.popen(line)",
        "import pickle",
        "__import__(name)",
    ],
)
def test_scanner_detects_forbidden_surface(snippet: str) -> None:
    assert _violations(ast.parse(snippet)) != []
