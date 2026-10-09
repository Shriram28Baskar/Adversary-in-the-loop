from __future__ import annotations

import math
from decimal import Decimal
from typing import Any

import pytest

from aitl_common.canonical_json import CanonicalJSONError, canonical_sha256, dumps, sha256_hex

# --- Golden vectors ---------------------------------------------------------------
# Byte strings are written out literally so they can be checked by eye.

GOLDEN: list[tuple[Any, bytes, str]] = [
    (
        {"b": 1, "a": [True, None, "é"]},
        b'{"a":[true,null,"\xc3\xa9"],"b":1}',
        "17c8c6f7f948ee1c9b93b1bc35f6edc29cbaf3022bff7d076d1c4831dd8a44a2",
    ),
    (
        {"z": {"y": [1, 2, {"x": "\n\t\x01"}]}, "": 0},
        b'{"":0,"z":{"y":[1,2,{"x":"\\n\\t\\u0001"}]}}',
        "16a1310d465e6f7cd7d324ff0b5c48bff61f93c62678fe535f429a1a195c5f5a",
    ),
]


@pytest.mark.parametrize(("value", "expected_bytes", "expected_hash"), GOLDEN)
def test_golden_vectors(value: Any, expected_bytes: bytes, expected_hash: str) -> None:
    assert dumps(value) == expected_bytes
    assert canonical_sha256(value) == expected_hash


def test_sha256_known_answer_vectors() -> None:
    # FIPS 180-2 / NIST test vectors.
    assert sha256_hex(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert sha256_hex(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_sha256_rejects_non_bytes() -> None:
    with pytest.raises(TypeError):
        sha256_hex("abc")  # type: ignore[arg-type]


# --- Determinism ------------------------------------------------------------------


def test_key_order_does_not_change_bytes() -> None:
    first = {"alpha": 1, "beta": {"y": 2, "x": 1}, "gamma": [3, 2, 1]}
    second = {"gamma": [3, 2, 1], "beta": {"x": 1, "y": 2}, "alpha": 1}
    assert dumps(first) == dumps(second)
    assert canonical_sha256(first) == canonical_sha256(second)


def test_list_order_is_significant() -> None:
    assert dumps([1, 2]) != dumps([2, 1])


def test_keys_sorted_by_code_point() -> None:
    assert dumps({"b": 0, "B": 0, "a": 0, "é": 0}) == b'{"B":0,"a":0,"b":0,"\xc3\xa9":0}'


def test_no_insignificant_whitespace() -> None:
    assert dumps({"a": [1, {"b": None}]}) == b'{"a":[1,{"b":null}]}'


def test_non_ascii_emitted_as_utf8_not_escaped() -> None:
    assert dumps("日本") == '"日本"'.encode()


def test_tuple_serializes_as_array() -> None:
    assert dumps((1, "x")) == dumps([1, "x"]) == b'[1,"x"]'


def test_bool_is_not_confused_with_int() -> None:
    assert dumps([True, 1, False, 0]) == b"[true,1,false,0]"


def test_finite_float_is_stable() -> None:
    assert dumps(0.1) == b"0.1"
    assert dumps(1.0) == b"1.0"
    assert dumps(-2.5e-10) == b"-2.5e-10"


def test_decimal_serialized_as_string() -> None:
    assert dumps({"temperature": Decimal("0.0")}) == b'{"temperature":"0.0"}'


def test_large_integers_preserved_exactly() -> None:
    assert dumps(2**70) == b"1180591620717411303424"


def test_repeated_calls_identical() -> None:
    value = {"k": [1, "two", 3.5, None, {"n": Decimal("1.25")}]}
    assert len({dumps(value) for _ in range(50)}) == 1


# --- Rejections -------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [math.nan, math.inf, -math.inf, Decimal("NaN"), Decimal("Infinity"), Decimal("-Infinity")],
)
def test_rejects_non_finite_numbers(value: Any) -> None:
    with pytest.raises(CanonicalJSONError):
        dumps({"x": [value]})


@pytest.mark.parametrize("key", [1, None, (1, 2), 1.5, True])
def test_rejects_non_string_keys(key: Any) -> None:
    with pytest.raises(CanonicalJSONError):
        dumps({key: 1})


@pytest.mark.parametrize("value", [b"bytes", {1, 2}, object(), complex(1, 2)])
def test_rejects_unsupported_types(value: Any) -> None:
    with pytest.raises(CanonicalJSONError):
        dumps([value])


def test_rejects_lone_surrogate() -> None:
    with pytest.raises(CanonicalJSONError):
        dumps("\ud800")


def test_error_reports_path() -> None:
    with pytest.raises(CanonicalJSONError, match=r"\$\.a\[1\]"):
        dumps({"a": [1, math.nan]})
