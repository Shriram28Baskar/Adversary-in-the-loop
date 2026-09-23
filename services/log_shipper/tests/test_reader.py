"""Reader and position state: bounded, restartable, never following links (P3)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from log_shipper.reader import (
    FIXTURE_FILE_PATTERN,
    LIVE_FILE_PATTERN,
    FilePosition,
    Line,
    Oversize,
    SourceReader,
    StateStore,
)


def reader(
    directory: Path,
    *,
    live: bool = False,
    max_line: int = 64,
    max_bytes: int = 10_000,
    max_lines: int = 100,
) -> SourceReader:
    return SourceReader(
        directory,
        LIVE_FILE_PATTERN if live else FIXTURE_FILE_PATTERN,
        max_line_bytes=max_line,
        max_bytes=max_bytes,
        max_lines=max_lines,
        complete_final_line=not live,
    )


def drain(r: SourceReader, positions: dict[str, FilePosition]) -> list[Line | Oversize]:
    items: list[Line | Oversize] = []
    for _ in range(100):
        cycle = r.read_cycle(positions)
        items.extend(cycle.items)
        positions.clear()
        positions.update(cycle.positions)
        if not cycle.pending:
            return items
    raise AssertionError("reader did not converge")


def test_reads_lines_with_deterministic_source_refs(tmp_path: Path) -> None:
    (tmp_path / "b.json").write_bytes(b"one\ntwo\n")
    (tmp_path / "a.json").write_bytes(b"zero\n")
    items = drain(reader(tmp_path), {})
    assert [(i.source_ref, i.data) for i in items if isinstance(i, Line)] == [
        ("a.json:0", b"zero"),
        ("b.json:0", b"one"),
        ("b.json:4", b"two"),
    ]


def test_fixture_final_line_without_newline_is_complete(tmp_path: Path) -> None:
    (tmp_path / "a.json").write_bytes(b"one\nlast")
    assert [i.data for i in drain(reader(tmp_path), {}) if isinstance(i, Line)] == [b"one", b"last"]


def test_live_partial_line_waits_for_its_newline(tmp_path: Path) -> None:
    log = tmp_path / "cowrie.json"
    log.write_bytes(b"one\npar")
    r = reader(tmp_path, live=True)
    positions: dict[str, FilePosition] = {}
    assert [i.data for i in drain(r, positions) if isinstance(i, Line)] == [b"one"]
    with open(log, "ab") as handle:
        handle.write(b"tial\n")
    assert [i.data for i in drain(r, positions) if isinstance(i, Line)] == [b"partial"]


def test_read_cycle_does_not_advance_stored_positions(tmp_path: Path) -> None:
    (tmp_path / "a.json").write_bytes(b"one\n")
    r = reader(tmp_path)
    positions: dict[str, FilePosition] = {}
    first = r.read_cycle(positions)
    again = r.read_cycle(positions)  # nothing committed: the same line again
    assert (
        [i.source_ref for i in first.items] == [i.source_ref for i in again.items] == ["a.json:0"]
    )


def test_oversize_line_is_reported_once_with_bounded_prefix(tmp_path: Path) -> None:
    (tmp_path / "a.json").write_bytes(b"ok\n" + b"x" * 500 + b"\nafter\n")
    items = drain(reader(tmp_path, max_line=64), {})
    kinds = [(type(i).__name__, i.source_ref) for i in items]
    assert kinds == [("Line", "a.json:0"), ("Oversize", "a.json:3"), ("Line", "a.json:504")]
    oversize = items[1]
    assert isinstance(oversize, Oversize)
    assert oversize.length_seen == 500


def test_unterminated_oversize_line_is_skipped_across_cycles(tmp_path: Path) -> None:
    log = tmp_path / "cowrie.json"
    log.write_bytes(b"x" * 300)
    r = reader(tmp_path, live=True, max_line=64, max_bytes=100)
    positions: dict[str, FilePosition] = {}
    items = drain(r, positions)
    assert [type(i).__name__ for i in items] == ["Oversize"]
    with open(log, "ab") as handle:
        handle.write(b"y" * 300 + b"\nnext\n")
    assert [i.data for i in drain(r, positions) if isinstance(i, Line)] == [b"next"]


def test_budgets_bound_each_cycle(tmp_path: Path) -> None:
    (tmp_path / "a.json").write_bytes(b"".join(b"line%03d\n" % i for i in range(50)))
    cycle = reader(tmp_path, max_lines=10).read_cycle({})
    assert len(cycle.items) == 10
    assert cycle.pending
    cycle = reader(tmp_path, max_bytes=20).read_cycle({})
    assert len(cycle.items) == 2
    assert cycle.pending


def test_rotation_keeps_position_and_truncation_restarts(tmp_path: Path) -> None:
    log = tmp_path / "cowrie.json"
    log.write_bytes(b"one\n")
    r = reader(tmp_path, live=True)
    positions: dict[str, FilePosition] = {}
    drain(r, positions)
    log.rename(tmp_path / "cowrie.json.2025-03-01")  # rotation: same inode
    (tmp_path / "cowrie.json").write_bytes(b"two\n")
    assert [i.data for i in drain(r, positions) if isinstance(i, Line)] == [b"two"]
    (tmp_path / "cowrie.json").write_bytes(b"")  # truncated
    (tmp_path / "cowrie.json").write_bytes(b"3\n")
    assert [i.data for i in drain(r, positions) if isinstance(i, Line)] == [b"3"]


@pytest.mark.parametrize(
    "name",
    [
        ".hidden.json",
        "A.json",
        "a.json.bak",
        "a.jsonl",
        "cowrie.log",
        "notes.txt",
        "a b.json",
    ],
)
def test_only_pattern_matching_files_are_read(tmp_path: Path, name: str) -> None:
    (tmp_path / name).write_bytes(b"secret\n")
    assert drain(reader(tmp_path), {}) == []


@pytest.mark.parametrize("name", ["cowrie.json.evil", "cowrie.json.2025-3-1", "x.json"])
def test_live_mode_reads_only_cowrie_logs(tmp_path: Path, name: str) -> None:
    (tmp_path / name).write_bytes(b"x\n")
    assert drain(reader(tmp_path, live=True), {}) == []


def test_symlinks_are_never_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "passwd").write_bytes(b"root:x:0:0\n")
    source = tmp_path / "source"
    source.mkdir()
    os.symlink(outside / "passwd", source / "a.json")
    os.symlink(outside / "passwd", source / "cowrie.json")
    assert drain(reader(source), {}) == []
    assert drain(reader(source, live=True), {}) == []


def test_directories_are_not_read(tmp_path: Path) -> None:
    (tmp_path / "a.json").mkdir()
    assert drain(reader(tmp_path), {}) == []


def test_state_round_trips_atomically(tmp_path: Path) -> None:
    store = StateStore(tmp_path)
    assert store.positions == {}
    store.commit({"1:2": FilePosition("a.json", 10, False), "1:3": FilePosition("b", 0, True)})
    assert StateStore(tmp_path).positions == store.positions
    assert not (tmp_path / "positions.tmp").exists()


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        '{"version": 2, "files": {}}',
        '{"version": 1, "files": {"../x": {"name": "a", "offset": 1, "skipping": false}}}',
        '{"version": 1, "files": {"1:2": {"name": "a", "offset": -1, "skipping": false}}}',
        '{"version": 1, "files": {"1:2": {"name": "a", "offset": "1", "skipping": false}}}',
        '{"version": 1, "files": {"1:2": {"name": "a"}}}',
        "[]",
    ],
)
def test_corrupt_state_restarts_from_zero_never_partially(tmp_path: Path, content: str) -> None:
    (tmp_path / "positions.json").write_text(content)
    assert StateStore(tmp_path).positions == {}
