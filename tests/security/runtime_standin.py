"""A minimal local stand-in image for runtime isolation probes (P3).

Network reachability, mounts, credentials and cgroup limits are properties of
the container Docker creates from a Compose service definition, not of the
image it runs. The isolation tests therefore run the *exact* Compose service
definitions with only ``image``/``entrypoint``/``command`` swapped for this
stand-in: the host's own Python interpreter, its shared libraries and its
standard library, imported as a rootfs (no registry pull, so it also works
where the pinned Cowrie image cannot be fetched). It contains no shell and no
network tooling; probes are Python scripts passed on the command line.
"""

from __future__ import annotations

import io
import os
import re
import shutil
import subprocess
import sys
import sysconfig
import tarfile
from pathlib import Path

TAG = "aitl-standin-python:test"
PYTHON = "/usr/bin/python3"
SHIPPER_STATE_DIR = "/srv/aitl/state"
_SKIP_STDLIB = {"test", "idlelib", "tkinter", "turtledemo", "ensurepip", "site-packages", "lib2to3"}
_ETC_USERS = (
    "root:x:0:0:root:/root:/sbin/nologin\n"
    "cowrie:x:999:999:cowrie:/nonexistent:/sbin/nologin\n"
    "nobody:x:65534:65534:nobody:/nonexistent:/sbin/nologin\n"
)
_GROUP = "root:x:0:\ncowrie:x:999:\nnogroup:x:65534:\n"


def _shared_libraries(paths: list[Path]) -> set[Path]:
    libraries: set[Path] = set()
    for path in paths:
        result = subprocess.run(["ldd", str(path)], capture_output=True, text=True, check=False)
        for match in re.finditer(r"(/\S+)\s+\(0x", result.stdout):
            libraries.add(Path(match.group(1)))
    return libraries


def _add_file(tar: tarfile.TarFile, source: Path, target: str) -> None:
    info = tar.gettarinfo(str(source.resolve()), arcname=target.lstrip("/"))
    with open(source.resolve(), "rb") as handle:
        tar.addfile(info, handle)


def _add_text(tar: tarfile.TarFile, target: str, content: str, mode: int = 0o644) -> None:
    data = content.encode()
    info = tarfile.TarInfo(target.lstrip("/"))
    info.size, info.mode = len(data), mode
    tar.addfile(info, io.BytesIO(data))


def _add_dir(tar: tarfile.TarFile, target: str, mode: int = 0o755, owner: int = 0) -> None:
    info = tarfile.TarInfo(target.lstrip("/"))
    info.type, info.mode = tarfile.DIRTYPE, mode
    info.uid = info.gid = owner
    tar.addfile(info)


def build(workdir: Path) -> str:
    """Build (or reuse) the stand-in image; returns its tag."""
    python = Path(os.path.realpath(sys.executable))
    stdlib = Path(sysconfig.get_paths()["stdlib"])
    dynload = stdlib / "lib-dynload"
    version = f"python{sys.version_info.major}.{sys.version_info.minor}"
    archive = workdir / "standin.tar"
    with tarfile.open(archive, "w") as tar:
        for directory in ("etc", "tmp", "usr", "usr/bin", "usr/lib", "run", "proc", "sys", "dev"):
            _add_dir(tar, directory, 0o1777 if directory == "tmp" else 0o755)
        # Mirrors services/log_shipper/Dockerfile: the state volume's mount point is
        # owned by the shipper user, so a fresh named volume inherits it.
        for directory in ("srv", "srv/aitl"):
            _add_dir(tar, directory)
        _add_dir(tar, SHIPPER_STATE_DIR, 0o700, owner=65534)
        _add_text(tar, "etc/passwd", _ETC_USERS)
        _add_text(tar, "etc/group", _GROUP)
        _add_file(tar, python, PYTHON)
        # The interpreter finds its prefix from /usr/bin/python3 -> /usr/lib/pythonX.Y.
        for root, dirs, files in os.walk(stdlib):
            dirs[:] = [d for d in dirs if d not in _SKIP_STDLIB and d != "__pycache__"]
            for name in files:
                source = Path(root) / name
                relative = source.relative_to(stdlib)
                _add_file(tar, source, f"usr/lib/{version}/{relative}")
        extensions = sorted(dynload.glob("*.so")) if dynload.is_dir() else []
        added: set[str] = set()
        for library in sorted(_shared_libraries([python, *extensions])):
            for target in {str(library), f"/usr/lib/{library.name}"}:
                if target not in added:
                    added.add(target)
                    _add_parent_dirs(tar, target, added)
                    _add_file(tar, library, target)
    subprocess.run(
        ["docker", "import", "--change", f'ENTRYPOINT ["{PYTHON}"]', str(archive), TAG],
        check=True,
        capture_output=True,
    )
    archive.unlink()
    return TAG


def _add_parent_dirs(tar: tarfile.TarFile, target: str, added: set[str]) -> None:
    parts = Path(target).parent.parts[1:]
    for index in range(1, len(parts) + 1):
        directory = "/".join(parts[:index])
        if f"dir:{directory}" not in added and directory not in ("usr", "usr/lib", "usr/bin"):
            added.add(f"dir:{directory}")
            _add_dir(tar, directory)


def docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    result = subprocess.run(["docker", "info"], capture_output=True, check=False)
    return result.returncode == 0
