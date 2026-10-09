"""The strict YAML subset used for all trusted configuration (P2)."""

from __future__ import annotations

import pytest

from aitl_common.config import strict_yaml


def test_strict_yaml_accepts_the_json_scalar_subset() -> None:
    data = strict_yaml.load("a: 1\nb: [x, -2, 2.5, true, false, null, ~]\nc:\n")
    assert data == {"a": 1, "b": ["x", -2, 2.5, True, False, None, None], "c": None}


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ("v: yes", "yes"),
        ("v: no", "no"),
        ("v: on", "on"),
        ("v: 2024-01-01", "2024-01-01"),
        ("v: 0o17", "0o17"),
        ("v: 0x1F", "0x1F"),
        ("v: .inf", ".inf"),
        ("v: .nan", ".nan"),
        ("v: 1e3", "1e3"),
        ("v: 1_000", "1_000"),
    ],
)
def test_strict_yaml_implicit_typing_is_json_only(text: str, value: str) -> None:
    """YAML 1.1 surprises (Norway problem, dates, octal, inf) stay plain strings."""
    assert strict_yaml.load(text) == {"v": value}


@pytest.mark.parametrize(
    ("text", "kind"),
    [
        ("a: 1\na: 2\n", "duplicate_key"),
        ("a:\n  b: 1\n  b: 2\n", "duplicate_key"),
        ("a: &x 1\nb: *x\n", "forbidden_construct"),
        ("a: {x: 1}\nb:\n  <<: {y: 2}\n", "forbidden_construct"),
        ("a: !!python/object/apply:os.system ['id']\n", "forbidden_construct"),
        ("a: !!python/name:os.system\n", "forbidden_construct"),
        ("a: !!binary aGk=\n", "forbidden_construct"),
        ("a: !!timestamp 2020-01-01\n", "forbidden_construct"),
        ("a: !!set {x}\n", "forbidden_construct"),
        ("a: !custom x\n", "forbidden_construct"),
        ("1: a\n", "forbidden_construct"),
        ("? [a, b]\n: c\n", "forbidden_construct"),
        ("a: [1, 2\n", "syntax"),
        ("", "syntax"),
        ("a: 1\n---\nb: 2\n", "syntax"),
    ],
)
def test_strict_yaml_rejects(text: str, kind: str) -> None:
    with pytest.raises(strict_yaml.StrictYAMLError) as caught:
        strict_yaml.load(text)
    assert caught.value.kind == kind
