from __future__ import annotations

import io
import json
import logging
import uuid
from typing import Any

import pytest

from aitl_common.logging import (
    CYCLE,
    MAX_DEPTH,
    REDACTED,
    TOO_DEEP,
    JsonFormatter,
    configure_logging,
    correlation_scope,
    current_correlation,
    log_event,
    parse_correlation_id,
    redact,
)


@pytest.fixture
def captured() -> tuple[logging.Logger, io.StringIO]:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    logger = logging.getLogger(f"test.{uuid.uuid4()}")
    logger.handlers[:] = [handler]
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    return logger, stream


def _lines(stream: io.StringIO) -> list[dict[str, Any]]:
    raw = stream.getvalue().splitlines()
    return [json.loads(line) for line in raw]


def test_event_is_single_line_json(captured: tuple[logging.Logger, io.StringIO]) -> None:
    logger, stream = captured
    log_event(logger, logging.INFO, "gateway.decision", tool="file_read", seq=3)
    [record] = _lines(stream)
    assert record["event"] == "gateway.decision"
    assert record["fields"] == {"tool": "file_read", "seq": 3}
    assert record["level"] == "INFO"


def test_attacker_newlines_and_escapes_cannot_forge_lines(
    captured: tuple[logging.Logger, io.StringIO],
) -> None:
    logger, stream = captured
    hostile = 'ls\n{"level":"CRITICAL","event":"forged"}\r\x1b[2J\x1b]0;pwn\x07\u2028'
    log_event(logger, logging.INFO, "intel.event_promoted", command=hostile)
    text = stream.getvalue()
    assert text.count("\n") == 1  # exactly one line, terminated
    assert text.isascii()
    assert "\x1b" not in text
    assert "\r" not in text
    [record] = _lines(stream)
    assert record["fields"]["command"] == hostile  # preserved as data, not interpreted


def test_attacker_format_specifiers_are_not_interpreted(
    captured: tuple[logging.Logger, io.StringIO],
) -> None:
    logger, stream = captured
    log_event(logger, logging.INFO, "intel.event_promoted", command="%s%s%n %(x)s {0}")
    [record] = _lines(stream)
    assert record["fields"]["command"] == "%s%s%n %(x)s {0}"


@pytest.mark.parametrize("event", ["", "Bad", "a b", "x\ny", "a..b", "a.%s", "../etc"])
def test_event_name_must_be_constant_identifier(
    captured: tuple[logging.Logger, io.StringIO], event: str
) -> None:
    logger, _ = captured
    with pytest.raises(ValueError, match="invalid event name"):
        log_event(logger, logging.INFO, event)


def test_third_party_malformed_format_does_not_raise() -> None:
    # Formatter tested directly: pytest attaches its own capture handlers to every
    # logger, and those re-raise stdlib format errors independently of ours.
    record = logging.LogRecord("third.party", logging.INFO, __file__, 1, "value %d", ("x",), None)
    rendered = json.loads(JsonFormatter().format(record))
    assert rendered["message"].startswith("<unformattable message")


@pytest.mark.parametrize(
    "key",
    [
        "password",
        "db_password",
        "POSTGRES_PASSWORD",
        "secret",
        "client-secret",
        "token",
        "capability_token",
        "api_key",
        "apiKey",
        "llm-api-key",
        "Authorization",
        "cookie",
        "credential",
        "private_key",
    ],
)
def test_credential_fields_redacted(captured: tuple[logging.Logger, io.StringIO], key: str) -> None:
    logger, stream = captured
    log_event(logger, logging.INFO, "service.started", **{key: "super-secret-value"})
    text = stream.getvalue()
    assert "super-secret-value" not in text
    [record] = _lines(stream)
    assert record["fields"][key] == REDACTED


def test_redaction_is_recursive_and_catches_bearer_values(
    captured: tuple[logging.Logger, io.StringIO],
) -> None:
    logger, stream = captured
    log_event(
        logger,
        logging.INFO,
        "http.request",
        headers={"X-Trace": "ok", "Authorization": "Bearer abc"},
        items=[{"token": "t1"}, "Bearer xyz"],
    )
    text = stream.getvalue()
    for leaked in ("abc", "t1", "xyz"):
        assert f'"{leaked}' not in text
        assert f" {leaked}" not in text
    [record] = _lines(stream)
    assert record["fields"]["headers"] == {"X-Trace": "ok", "Authorization": REDACTED}
    assert record["fields"]["items"] == [{"token": REDACTED}, REDACTED]


def test_non_secret_fields_preserved() -> None:
    fields = {"input_tokens": 12, "tool": "file_read", "session_id": "s", "path": "/public/x"}
    assert redact(fields) == fields


def test_unserializable_value_does_not_break_logging(
    captured: tuple[logging.Logger, io.StringIO],
) -> None:
    logger, stream = captured

    class Weird:
        def __str__(self) -> str:
            raise RuntimeError("boom")

    log_event(logger, logging.INFO, "a.b", weird=Weird())
    [record] = _lines(stream)
    assert record["fields"]["weird"].startswith("<unserializable")


def test_circular_structure_is_marked_not_recursed(
    captured: tuple[logging.Logger, io.StringIO],
) -> None:
    logger, stream = captured
    circular: list[Any] = [1]
    circular.append(circular)
    log_event(logger, logging.INFO, "a.c", loop=circular)
    [record] = _lines(stream)
    assert record["fields"]["loop"] == [1, CYCLE]


def test_repeated_non_circular_references_are_kept() -> None:
    shared = {"k": 1}
    assert redact({"a": shared, "b": shared}) == {"a": {"k": 1}, "b": {"k": 1}}


def test_excessive_nesting_is_truncated() -> None:
    deep: Any = "leaf"
    for _ in range(MAX_DEPTH + 10):
        deep = [deep]
    redacted = redact(deep)
    for _ in range(MAX_DEPTH):
        redacted = redacted[0]
    assert redacted == TOO_DEEP


def test_non_finite_numbers_never_produce_invalid_json(
    captured: tuple[logging.Logger, io.StringIO],
) -> None:
    logger, stream = captured
    log_event(logger, logging.INFO, "a.d", value=float("nan"))
    [record] = _lines(stream)  # json.loads would accept NaN; the line must not contain it
    assert "NaN" not in stream.getvalue()
    assert "fields" not in record
    assert record["log_error"] == "fields not serializable"


def test_exception_info_is_escaped(captured: tuple[logging.Logger, io.StringIO]) -> None:
    logger, stream = captured
    try:
        raise ValueError("line1\nline2")
    except ValueError:
        logger.exception("failure")
    assert stream.getvalue().count("\n") == 1
    [record] = _lines(stream)
    assert record["exc_type"] == "ValueError"


def test_correlation_scope_binds_and_resets(captured: tuple[logging.Logger, io.StringIO]) -> None:
    logger, stream = captured
    cid, eid, pid = (str(uuid.uuid4()) for _ in range(3))
    assert current_correlation() == {}
    with correlation_scope(correlation_id=cid, execution_id=eid, pair_id=pid):
        log_event(logger, logging.INFO, "x.y")
        with correlation_scope(execution_id=str(uuid.uuid4())):
            assert current_correlation()["correlation_id"] == cid
    assert current_correlation() == {}
    [record] = _lines(stream)
    assert (record["correlation_id"], record["execution_id"], record["pair_id"]) == (cid, eid, pid)


def test_correlation_scope_generates_id_when_absent() -> None:
    with correlation_scope() as cid:
        assert uuid.UUID(cid)
        assert current_correlation() == {"correlation_id": cid}


@pytest.mark.parametrize("bad", ["", "not-a-uuid", "x" * 36, "1234", str(uuid.uuid4()) + "\n"])
def test_correlation_scope_rejects_non_uuid(bad: str) -> None:
    with (
        pytest.raises(ValueError, match="execution_id must be"),
        correlation_scope(execution_id=bad),
    ):
        pass


def test_parse_correlation_id_accepts_only_canonical_uuid() -> None:
    valid = str(uuid.uuid4())
    assert parse_correlation_id(valid) == valid
    for hostile in (None, "", "abc", valid + "\ninjected", valid.upper() + "x", "{" + valid + "}"):
        replaced = parse_correlation_id(hostile)
        assert replaced != hostile
        assert uuid.UUID(replaced)


def test_configure_logging_installs_json_formatter() -> None:
    stream = io.StringIO()
    root = logging.getLogger()
    previous_handlers, previous_level = root.handlers[:], root.level
    try:
        configure_logging(stream=stream)
        log_event(logging.getLogger("svc"), logging.INFO, "svc.ready")
        assert json.loads(stream.getvalue())["event"] == "svc.ready"
    finally:
        root.handlers[:] = previous_handlers
        root.setLevel(previous_level)
