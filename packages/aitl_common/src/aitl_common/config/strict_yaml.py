"""A deliberately small YAML subset for trusted configuration.

PyYAML's ``safe_load`` still accepts constructs that make configuration
ambiguous or surprising, so this loader rejects them outright:

- duplicate mapping keys (``safe_load`` silently keeps the last one);
- anchors, aliases and merge keys (``<<``);
- explicit tags of any kind (``!!python/...``, ``!!binary``, ``!!timestamp``,
  ``!!set``, custom ``!tags``);
- non-string mapping keys.

Implicit typing is reduced to JSON's scalars: ``true``/``false``, ``null``
(``null``, ``~`` or empty), base-10 integers and plain decimal floats.
Everything else - including ``yes``/``no``/``on``/``off``, dates, octal, hex,
``.inf`` and ``.nan`` - is a string, and the schema then rejects it where a
number or boolean is required. No code is ever executed while loading.
"""

from __future__ import annotations

import re
from typing import Any

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

__all__ = ["StrictYAMLError", "load"]

_STR = "tag:yaml.org,2002:str"
_INT = "tag:yaml.org,2002:int"
_FLOAT = "tag:yaml.org,2002:float"
_BOOL = "tag:yaml.org,2002:bool"
_NULL = "tag:yaml.org,2002:null"
_SEQ = "tag:yaml.org,2002:seq"
_MAP = "tag:yaml.org,2002:map"
_ALLOWED_TAGS = frozenset({_STR, _INT, _FLOAT, _BOOL, _NULL, _SEQ, _MAP})


class StrictYAMLError(ValueError):
    def __init__(self, kind: str, message: str, line: int | None = None) -> None:
        self.kind = kind  # "syntax" | "duplicate_key" | "forbidden_construct"
        self.line = line
        where = f" (line {line})" if line is not None else ""
        super().__init__(f"{message}{where}")


class _StrictResolver(yaml.resolver.BaseResolver):
    pass


_StrictResolver.yaml_implicit_resolvers = {}
for _tag, _pattern, _first in (
    (_BOOL, r"^(?:true|false)$", list("tf")),
    (_NULL, r"^(?:~|null|)$", ["~", "n", ""]),
    (_INT, r"^[-+]?(?:0|[1-9][0-9]*)$", list("-+0123456789")),
    (_FLOAT, r"^[-+]?(?:0|[1-9][0-9]*)\.[0-9]+$", list("-+0123456789")),
):
    _StrictResolver.add_implicit_resolver(_tag, re.compile(_pattern), _first)


class _StrictConstructor(yaml.constructor.SafeConstructor):
    def construct_object(self, node: Node, deep: bool = False) -> Any:
        if node.tag not in _ALLOWED_TAGS:
            raise StrictYAMLError(
                "forbidden_construct", f"tag {node.tag!r} is not allowed", _line(node)
            )
        return super().construct_object(node, deep=deep)

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Any, Any]:
        if not isinstance(node, MappingNode):
            raise StrictYAMLError("forbidden_construct", "expected a mapping", _line(node))
        mapping: dict[str, Any] = {}
        for key_node, value_node in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge" or (
                isinstance(key_node, ScalarNode) and key_node.value == "<<" and not key_node.style
            ):
                raise StrictYAMLError(
                    "forbidden_construct", "merge keys are not allowed", _line(key_node)
                )
            if not (isinstance(key_node, ScalarNode) and key_node.tag == _STR):
                raise StrictYAMLError(
                    "forbidden_construct", "mapping keys must be strings", _line(key_node)
                )
            key = self.construct_scalar(key_node)
            if key in mapping:
                raise StrictYAMLError("duplicate_key", f"duplicate key {key!r}", _line(key_node))
            mapping[str(key)] = self.construct_object(value_node, deep=True)
        return mapping


class _StrictLoader(
    yaml.reader.Reader,
    yaml.scanner.Scanner,
    yaml.parser.Parser,
    yaml.composer.Composer,
    _StrictConstructor,
    _StrictResolver,
):
    def __init__(self, stream: str) -> None:
        yaml.reader.Reader.__init__(self, stream)
        yaml.scanner.Scanner.__init__(self)
        yaml.parser.Parser.__init__(self)
        yaml.composer.Composer.__init__(self)
        _StrictConstructor.__init__(self)
        _StrictResolver.__init__(self)

    def compose_node(self, parent: Node | None, index: int) -> Node | None:
        event = self.peek_event()  # type: ignore[no-untyped-call]
        mark = getattr(event, "start_mark", None)
        line = None if mark is None else int(mark.line) + 1
        if isinstance(event, yaml.AliasEvent):
            raise StrictYAMLError("forbidden_construct", "aliases are not allowed", line)
        if getattr(event, "anchor", None) is not None:
            raise StrictYAMLError("forbidden_construct", "anchors are not allowed", line)
        node: Node | None = super().compose_node(parent, index)
        return node


_StrictConstructor.add_constructor(_MAP, _StrictConstructor.construct_mapping)  # type: ignore[type-var]
_StrictConstructor.add_constructor(  # type: ignore[type-var]
    _SEQ, yaml.constructor.SafeConstructor.construct_yaml_seq
)


def _line(node: Node) -> int | None:
    mark = getattr(node, "start_mark", None)
    return None if mark is None else int(mark.line) + 1


def _materialize(value: Any) -> Any:
    # construct_yaml_seq/map are generators in PyYAML; force plain containers.
    if isinstance(value, dict):
        return {key: _materialize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_materialize(item) for item in value]
    return value


def _check_node(node: Node) -> None:
    if node.tag not in _ALLOWED_TAGS:
        raise StrictYAMLError(
            "forbidden_construct", f"tag {node.tag!r} is not allowed", _line(node)
        )
    if isinstance(node, SequenceNode):
        for child in node.value:
            _check_node(child)
    elif isinstance(node, MappingNode):
        for key, value in node.value:
            _check_node(key)
            _check_node(value)


def load(text: str) -> Any:
    """Parse one YAML document under the strict subset; raise StrictYAMLError."""
    loader = _StrictLoader(text)
    try:
        node = loader.get_single_node()
        if node is None:
            raise StrictYAMLError("syntax", "document is empty")
        _check_node(node)
        return _materialize(loader.construct_document(node))
    except StrictYAMLError:
        raise
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        line = None if mark is None else int(mark.line) + 1
        raise StrictYAMLError("syntax", str(getattr(exc, "problem", None) or exc), line) from exc
    finally:
        loader.dispose()
