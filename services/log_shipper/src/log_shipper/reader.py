"""Bounded, restartable line reader over one read-only directory.

Used identically by live mode (Cowrie's log directory, mounted read-only) and
fixture mode (the version-controlled corpus, mounted read-only), so fixture
replay takes exactly the same path as live telemetry (FR-005b).

- Only regular files whose names match the mode's fixed pattern are read;
  symlinks and anything else are ignored, never followed or opened.
- Files are identified by (device, inode), so a rotated file keeps its
  position; a file that shrank (truncated) is re-read from 0, which the
  staging keys make harmless (migration 0014).
- Each cycle reads at most ``max_bytes`` and ``max_lines``. A line longer
  than ``max_line_bytes`` is reported once as ``Oversize`` (with a bounded
  prefix) and skipped to its end without buffering it.
- ``read_cycle`` never changes the stored positions; the caller commits the
  returned positions only after the database write succeeded, so nothing is
  lost when the database is unavailable (at-least-once, de-duplicated).
"""

from __future__ import annotations

import errno
import json
import os
import re
import stat
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Final

__all__ = [
    "FIXTURE_FILE_PATTERN",
    "LIVE_FILE_PATTERN",
    "FilePosition",
    "Line",
    "Oversize",
    "SourceReader",
    "StateStore",
]

LIVE_FILE_PATTERN: Final = re.compile(r"cowrie\.json(?:\.[0-9]{4}-[0-9]{2}-[0-9]{2})?")
FIXTURE_FILE_PATTERN: Final = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\.json")
OVERSIZE_PREFIX_BYTES: Final = 8192
_STATE_VERSION: Final = 1


@dataclass(frozen=True, slots=True)
class FilePosition:
    name: str
    offset: int
    skipping: bool = False  # inside an oversize line whose end is not yet read


@dataclass(frozen=True, slots=True)
class Line:
    source_ref: str
    data: bytes


@dataclass(frozen=True, slots=True)
class Oversize:
    source_ref: str
    prefix: bytes
    length_seen: int


Item = Line | Oversize


@dataclass(frozen=True, slots=True)
class Cycle:
    items: list[Item]
    positions: dict[str, FilePosition]
    pending: bool  # unread complete data remained after this cycle


class StateStore:
    """Positions per file identity, persisted atomically in the shipper's own volume."""

    def __init__(self, directory: Path) -> None:
        self.path = directory / "positions.json"
        self.positions: dict[str, FilePosition] = self._load()

    def _load(self) -> dict[str, FilePosition]:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            if raw.get("version") != _STATE_VERSION:
                return {}
            loaded = {}
            for key, entry in raw["files"].items():
                if not re.fullmatch(r"[0-9]+:[0-9]+", key):
                    return {}
                name, offset, skipping = entry["name"], entry["offset"], entry["skipping"]
                if not (
                    isinstance(name, str)
                    and isinstance(offset, int)
                    and offset >= 0
                    and isinstance(skipping, bool)
                ):
                    return {}
                loaded[key] = FilePosition(name, offset, skipping)
            return loaded
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            # Unreadable state restarts from the beginning: safe, because staging
            # de-duplicates (migration 0014). Never trusted partially.
            return {}

    def commit(self, positions: dict[str, FilePosition]) -> None:
        self.positions = dict(positions)
        document = {
            "version": _STATE_VERSION,
            "files": {
                key: {"name": p.name, "offset": p.offset, "skipping": p.skipping}
                for key, p in sorted(positions.items())
            },
        }
        tmp = self.path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(document, handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, self.path)
        directory = os.open(self.path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


class SourceReader:
    def __init__(
        self,
        directory: Path,
        pattern: re.Pattern[str],
        *,
        max_line_bytes: int,
        max_bytes: int,
        max_lines: int,
        complete_final_line: bool,
    ) -> None:
        self.directory = directory
        self.pattern = pattern
        self.max_line_bytes = max_line_bytes
        self.max_bytes = max_bytes
        self.max_lines = max_lines
        # Fixture files are static, so an unterminated last line is complete;
        # a live log's unterminated last line may still be being written.
        self.complete_final_line = complete_final_line

    def _files(self) -> list[tuple[str, str, int]]:
        """(identity, name, size) of regular, pattern-matching files; deterministic order."""
        found = []
        for entry in os.scandir(self.directory):
            if not self.pattern.fullmatch(entry.name) or entry.is_symlink():
                continue
            info = entry.stat(follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode):
                continue
            found.append((f"{info.st_dev}:{info.st_ino}", entry.name, info.st_size))
        # Rotated (dated) live files before the current one; fixtures by name.
        return sorted(found, key=lambda f: (f[1] == "cowrie.json", f[1]))

    def read_cycle(self, positions: dict[str, FilePosition]) -> Cycle:
        items: list[Item] = []
        new_positions: dict[str, FilePosition] = {}
        budget = self.max_bytes
        pending = False
        for key, name, size in self._files():
            position = positions.get(key, FilePosition(name, 0))
            if size < position.offset:
                position = FilePosition(position.name, 0)  # truncated: re-read (de-duplicated)
            if budget <= 0 or len(items) >= self.max_lines:
                new_positions[key] = position
                pending = pending or size > position.offset
                continue
            position, budget, more = self._read_file(name, size, position, budget, items)
            new_positions[key] = position
            pending = pending or more
        return Cycle(items, new_positions, pending)

    def _read_file(
        self,
        name: str,
        size: int,
        position: FilePosition,
        budget: int,
        items: list[Item],
    ) -> tuple[FilePosition, int, bool]:
        want = min(size - position.offset, budget)
        if want <= 0:
            return position, budget, False
        try:
            fd = os.open(self.directory / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError as exc:
            if exc.errno in (errno.ENOENT, errno.ELOOP):
                return position, budget, False
            raise
        try:
            os.lseek(fd, position.offset, os.SEEK_SET)
            chunks = []
            remaining = want
            while remaining > 0:
                chunk = os.read(fd, min(remaining, 1 << 20))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            buffer = b"".join(chunks)
        finally:
            os.close(fd)

        base = position.offset
        cursor = 0
        skipping = position.skipping
        at_eof = base + len(buffer) >= size
        waiting = False  # stopped at an incomplete live line: nothing more to do now
        while cursor < len(buffer) and len(items) < self.max_lines:
            newline = buffer.find(b"\n", cursor)
            if skipping:
                if newline < 0:
                    cursor = len(buffer)
                    break
                cursor = newline + 1
                skipping = False
                continue
            if newline >= 0:
                end = newline
            elif at_eof and self.complete_final_line:
                end = len(buffer)
            else:
                if len(buffer) - cursor > self.max_line_bytes:
                    # An unterminated line already longer than any legal line.
                    items.append(
                        Oversize(
                            f"{name}:{base + cursor}",
                            buffer[cursor : cursor + OVERSIZE_PREFIX_BYTES],
                            len(buffer) - cursor,
                        )
                    )
                    cursor = len(buffer)
                    skipping = True
                waiting = True
                break  # partial line: wait for the rest
            line = buffer[cursor:end]
            ref = f"{name}:{base + cursor}"
            if len(line) > self.max_line_bytes:
                items.append(Oversize(ref, line[:OVERSIZE_PREFIX_BYTES], len(line)))
            elif line:
                items.append(Line(ref, line))
            cursor = end + 1 if newline >= 0 else end
        consumed = min(cursor, len(buffer))
        new_position = replace(
            position, name=position.name, offset=base + consumed, skipping=skipping
        )
        more = not at_eof or (consumed < len(buffer) and not waiting)
        return new_position, budget - consumed, more
