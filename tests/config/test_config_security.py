"""Security invariants of the configuration layer (P2).

Properties are checked exhaustively over the real v1 artifacts where the space
is finite, and over deterministic generated inputs otherwise (no randomness):

- the four-tool / two-endpoint boundary cannot be widened from YAML;
- unknown fields are rejected at every nesting level of every YAML artifact;
- unknown ATT&CK techniques and tactics never validate;
- configuration code cannot execute, import or shell out, and exposes no API
  that turns strings or database rows into configuration;
- scenario templates have no field that can carry or reference attacker data;
- fabricated fixture credentials never appear outside their own asset,
  anywhere in the repository (FR-004c, SEC-003);
- the controlled vocabulary is identical to the database enums;
- formatting-only changes never change a content hash.
"""

from __future__ import annotations

import ast
import inspect
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any, get_args

import pytest
from pydantic import BaseModel, TypeAdapter

from aitl_common.config import bundle as bundle_module
from aitl_common.config import loader as loader_module
from aitl_common.config.bundle import load_config
from aitl_common.config.errors import ConfigValidationError, IssueType
from aitl_common.config.loader import ConfigRoot
from aitl_common.config.schemas.abstraction import AbstractionTable
from aitl_common.config.schemas.agents import AgentConfig, ScriptedPlan
from aitl_common.config.schemas.attack import CURATED_TECHNIQUES, AttackMapping
from aitl_common.config.schemas.evaluation import EvalConfig
from aitl_common.config.schemas.fixtures import FixtureSetManifest, TabularData
from aitl_common.config.schemas.intel import PhaseRules, TtpRules
from aitl_common.config.schemas.policies import Policy
from aitl_common.config.schemas.scenarios import ScenarioTemplate
from aitl_common.config.schemas.tasks import AgentTaskDefinition
from aitl_common.config.schemas.tools import MockEndpoints, ToolDefinitions, ToolSet
from aitl_common.config.vocabulary import DB_ENUMS, MOCK_ENDPOINTS, TOOL_NAMES
from aitl_common.db.types import ENUM_LABELS
from tests.config.helpers import CONFIG_ROOT, REPO_ROOT, copy_config, mutate, read_yaml, write_yaml

CONFIG_SRC = REPO_ROOT / "packages" / "aitl_common" / "src" / "aitl_common" / "config"

SCHEMA_FOR: dict[str, Any] = {
    "attack/attack_mapping_v1.yaml": AttackMapping,
    "intel/phase_rules_v1.yaml": PhaseRules,
    "intel/ttp_rules_v1.yaml": TtpRules,
    "abstraction/abstraction_table_v1.yaml": AbstractionTable,
    "scenarios/template_library_v1/T-01.yaml": ScenarioTemplate,
    "scenarios/template_library_v1/T-02.yaml": ScenarioTemplate,
    "scenarios/template_library_v1/T-03.yaml": ScenarioTemplate,
    "tasks/TK-1_v1.yaml": AgentTaskDefinition,
    "tools/tool_definitions_v1.yaml": ToolDefinitions,
    "fixtures/fixture_set_v1/manifest.yaml": FixtureSetManifest,
    "fixtures/fixture_set_v1/db/products.yaml": TabularData,
    "fixtures/fixture_set_v1/db/employees.yaml": TabularData,
    "fixtures/fixture_set_v1/db/api_keys.yaml": TabularData,
    "fixtures/fixture_set_v1/api/directory.yaml": TabularData,
    "agents/assistant_llm_v1.yaml": TypeAdapter(AgentConfig),
    "agents/assistant_scripted_v1.yaml": TypeAdapter(AgentConfig),
    "agents/scripted_plans/T-01.yaml": ScriptedPlan,
    "agents/scripted_plans/T-02.yaml": ScriptedPlan,
    "agents/scripted_plans/T-03.yaml": ScriptedPlan,
    "policies/baseline-permissive_v1.yaml": Policy,
    "policies/target_v1.yaml": Policy,
    "eval/eval-v1.yaml": EvalConfig,
}


def test_schema_table_covers_every_yaml_artifact() -> None:
    tracked = {str(p.relative_to(CONFIG_ROOT)) for p in CONFIG_ROOT.rglob("*.yaml") if p.is_file()}
    assert tracked == set(SCHEMA_FOR)


# --- vocabulary ----------------------------------------------------------------------


@pytest.mark.parametrize("enum_name", sorted(DB_ENUMS))
def test_vocabulary_matches_database_enums(enum_name: str) -> None:
    assert get_args(DB_ENUMS[enum_name]) == ENUM_LABELS[enum_name]


# --- four-tool boundary ------------------------------------------------------------------

FORBIDDEN_TOOLS = [
    "send_email",
    "shell",
    "terminal",
    "bash",
    "http",
    "http_request",
    "fetch_url",
    "browser",
    "write_file",
    "file_write",
    "code_execution",
    "python",
    "exec",
    "sql",
    "raw_sql",
    "plugin",
    "dynamic_tool",
]


def test_tool_set_is_exactly_the_four_mvp_tools() -> None:
    assert tuple(ToolSet.model_fields) == TOOL_NAMES
    assert TOOL_NAMES == ("file_search", "file_read", "database_query", "mock_api")
    assert tuple(MockEndpoints.model_fields) == MOCK_ENDPOINTS
    assert ENUM_LABELS["tool_name"] == TOOL_NAMES
    bundle = load_config(CONFIG_ROOT)
    for tools in bundle.tool_definitions.values():
        assert set(tools.model.entries()) == {
            ("file_search", None),
            ("file_read", None),
            ("database_query", None),
            ("mock_api", "directory_lookup"),
            ("mock_api", "send_message"),
        }


@pytest.mark.parametrize("tool", FORBIDDEN_TOOLS)
def test_no_artifact_can_introduce_a_tool(tmp_path: Path, tool: str) -> None:
    root = copy_config(tmp_path)
    cases = [
        (
            "tools/tool_definitions_v1.yaml",
            lambda d: d["tools"].update({tool: d["tools"]["file_read"]}),
        ),
        (
            "tools/tool_definitions_v1.yaml",
            lambda d: d["tools"]["mock_api"]["endpoints"].update(
                {tool: d["tools"]["mock_api"]["endpoints"]["directory_lookup"]}
            ),
        ),
        ("policies/target_v1.yaml", lambda d: d["permission_rules"][0].update(tool=tool)),
        ("policies/target_v1.yaml", lambda d: d["permission_rules"][7].update(endpoint=tool)),
        (
            "agents/scripted_plans/T-02.yaml",
            lambda d: d["variants"]["file:/sensitive/deploy_credentials.txt"][0].update(tool=tool),
        ),
        (
            "scenarios/template_library_v1/T-02.yaml",
            lambda d: d["variants"]["file:/sensitive/deploy_credentials.txt"]["steps"][2].update(
                tool=tool
            ),
        ),
    ]
    for relative, change in cases:
        original = (root / relative).read_bytes()
        mutate(root, relative, change)
        with pytest.raises(ConfigValidationError) as caught:
            ConfigRoot(root).load_yaml(relative, SCHEMA_FOR[relative])
        assert caught.value.types() & {
            IssueType.UNKNOWN_FIELD,
            IssueType.INVALID_ENUM,
        }, (relative, caught.value.to_dicts())
        (root / relative).write_bytes(original)


# --- unknown fields at every level ---------------------------------------------------------


def _mapping_paths(value: Any, path: tuple[Any, ...] = ()) -> Iterator[tuple[Any, ...]]:
    if isinstance(value, dict):
        yield path
        for key, item in value.items():
            yield from _mapping_paths(item, (*path, key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _mapping_paths(item, (*path, index))


def _node(data: Any, path: tuple[Any, ...]) -> Any:
    for part in path:
        data = data[part]
    return data


@pytest.mark.parametrize("relative", sorted(SCHEMA_FOR))
@pytest.mark.parametrize(
    "key", ["exec", "import_path", "command", "url", "source_reference", "zz_extra"]
)
def test_unknown_field_rejected_at_every_level(tmp_path: Path, relative: str, key: str) -> None:
    """Injecting any key into any mapping of any artifact is rejected."""
    root = copy_config(tmp_path)
    data = read_yaml(root, relative)
    paths = list(_mapping_paths(data))
    assert paths
    for path in paths:
        mutated = read_yaml(root, relative)
        _node(mutated, path)[key] = "__import__('os').system('id')"
        write_yaml(root, relative, mutated)
        with pytest.raises(ConfigValidationError):
            ConfigRoot(root).load_yaml(relative, SCHEMA_FOR[relative])
    write_yaml(root, relative, data)


def test_formatting_round_trip_keeps_every_hash(tmp_path: Path) -> None:
    """Re-emitting every YAML artifact (no comments, different layout) keeps each hash."""
    root = copy_config(tmp_path)
    before = {r["source"]: r["sha256"] for r in load_config(CONFIG_ROOT).inventory()}
    for relative in SCHEMA_FOR:
        write_yaml(root, relative, read_yaml(root, relative))
    after = {r["source"]: r["sha256"] for r in load_config(root).inventory()}
    assert after == before


def test_hashes_do_not_depend_on_location_or_load_order(tmp_path: Path) -> None:
    a = load_config(CONFIG_ROOT).inventory()
    b = load_config(copy_config(tmp_path)).inventory()
    assert a == b
    assert a == load_config(CONFIG_ROOT).inventory()


# --- ATT&CK ------------------------------------------------------------------------------

UNCURATED = [
    f"T{n:04d}" for n in range(1001, 1700, 37) if f"T{n:04d}" not in CURATED_TECHNIQUES
] + ["T1552.002", "T1110.003", "T1059.001", "T1003.008", "TA0001", "TA0040"]


@pytest.mark.parametrize("element", UNCURATED)
def test_unknown_techniques_never_validate(tmp_path: Path, element: str) -> None:
    root = copy_config(tmp_path)
    mutate(
        root,
        "abstraction/abstraction_table_v1.yaml",
        lambda d: d["rules"][0].update(elements=[[element]]),
    )
    with pytest.raises(ConfigValidationError) as caught:
        load_config(root)
    assert IssueType.UNSUPPORTED_TECHNIQUE in caught.value.types()


@pytest.mark.parametrize("technique", [t for t in UNCURATED if not t.startswith("TA")])
def test_mapping_cannot_add_uncurated_technique(tmp_path: Path, technique: str) -> None:
    root = copy_config(tmp_path)
    mutate(
        root,
        "attack/attack_mapping_v1.yaml",
        lambda d: d["techniques"].append({"id": technique, "tactic_id": "TA0007", "name": "X"}),
    )
    with pytest.raises(ConfigValidationError) as caught:
        load_config(root)
    assert IssueType.UNSUPPORTED_TECHNIQUE in caught.value.types()


# --- no executable configuration -----------------------------------------------------------

FORBIDDEN_IMPORTS = {
    "importlib",
    "subprocess",
    "pickle",
    "marshal",
    "shelve",
    "ctypes",
    "runpy",
    "code",
    "socket",
    "urllib",
    "http",
    "requests",
    "httpx",
    "jinja2",
    "string",
}
FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__", "globals", "locals", "vars"}
# Reflection is allowed only with a literal attribute name (never a computed one).
REFLECTION_CALLS = {"getattr", "setattr", "hasattr", "delattr"}


def _config_sources() -> list[Path]:
    return sorted(CONFIG_SRC.rglob("*.py"))


@pytest.mark.parametrize("path", _config_sources(), ids=lambda p: p.name)
def test_config_code_cannot_execute_or_import_dynamically(path: Path) -> None:
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] not in FORBIDDEN_IMPORTS, alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            assert node.module.split(".")[0] not in FORBIDDEN_IMPORTS, node.module
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in FORBIDDEN_CALLS, (path.name, node.func.id)
            if node.func.id in REFLECTION_CALLS:
                name = node.args[1] if len(node.args) > 1 else None
                assert isinstance(name, ast.Constant), (path.name, node.lineno)
                assert isinstance(name.value, str), (path.name, node.lineno)
        elif isinstance(node, ast.Attribute):
            assert node.attr not in {"system", "popen", "spawn", "load_module"}, node.attr
    # PyYAML is used only through the strict loader: never yaml.load/unsafe_load/
    # full_load or the Full/Unsafe loaders.
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "yaml"
        ):
            assert node.attr not in {
                "load",
                "load_all",
                "unsafe_load",
                "full_load",
                "FullLoader",
                "UnsafeLoader",
                "Loader",
            }, (path.name, node.attr)


def test_only_the_registry_touches_the_database() -> None:
    for path in _config_sources():
        tree = ast.parse(path.read_text())
        modules = {
            n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module
        } | {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        uses_db = any(m.startswith(("sqlalchemy", "psycopg", "aitl_common.db")) for m in modules)
        assert uses_db == (path.name == "registry.py"), path.name


def test_registry_writes_only_configuration_tables() -> None:
    from aitl_common.config import registry

    tables = {value.name for value in vars(registry).values() if isinstance(value, registry._Table)}
    assert tables == {
        "agent.agent_config",
        "agent.agent_task",
        "agent.tool",
        "agent.data_asset",
        "security.policy",
        "eval.eval_config",
    }
    source = inspect.getsource(registry)
    for attacker_table in ("intel_raw", "attack_event", "attacker_behavior", "attack_session"):
        assert attacker_table not in source


def test_no_api_parses_configuration_from_strings_or_rows() -> None:
    """Configuration enters only as files under a root directory."""
    public = [
        obj
        for module in (loader_module, bundle_module)
        for name, obj in vars(module).items()
        if not name.startswith("_")
        and inspect.isfunction(obj)
        and obj.__module__ == module.__name__
    ]
    assert [f.__name__ for f in public] == ["content_sha256", "load_config"]
    assert inspect.signature(load_config).parameters["root"].annotation in ("Path", Path)
    root_methods = {
        name
        for name, _ in inspect.getmembers(ConfigRoot, inspect.isfunction)
        if not name.startswith("_")
    }
    assert root_methods == {"exists", "list_dir", "read", "load_text", "load_yaml"}
    for name in ("read", "load_text", "load_yaml", "list_dir", "exists"):
        assert "relative" in inspect.signature(getattr(ConfigRoot, name)).parameters


# --- attacker data / abstraction boundary ----------------------------------------------------

ATTACKER_FIELD_NAMES = {
    "source_reference",
    "raw_text",
    "normalized_text",
    "attack_event_id",
    "attacker_behavior_id",
    "attack_session_id",
    "session_id",
    "ttp_id",
    "behavior_id",
    "event_id",
    "username",
    "attempted_secret",
    "command",
    "payload",
    "cowrie_session_id",
}


def _field_names(model: type[BaseModel], seen: set[type[BaseModel]] | None = None) -> set[str]:
    seen = set() if seen is None else seen
    if model in seen:
        return set()
    seen.add(model)
    names = set(model.model_fields)
    for field in model.model_fields.values():
        for candidate in _models_in(field.annotation):
            names |= _field_names(candidate, seen)
    return names


def _models_in(annotation: Any) -> Iterator[type[BaseModel]]:
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        yield annotation
    for arg in get_args(annotation):
        yield from _models_in(arg)


@pytest.mark.parametrize("model", [ScenarioTemplate, ScriptedPlan, AbstractionTable])
def test_generation_inputs_have_no_attacker_data_fields(model: type[BaseModel]) -> None:
    assert _field_names(model) & ATTACKER_FIELD_NAMES == set()


def test_template_references_only_abstraction_rules_and_fixtures() -> None:
    """Pattern compatibility is by abstraction rule + pattern enums; asset refs are
    fixture IDs, which can never be a UUID of an attack event."""
    bundle = load_config(CONFIG_ROOT)
    for loaded in bundle.template_libraries["template-library-v1"].templates.values():
        template = loaded.model
        assert all(r.startswith("AR-") for r in template.compatible_with.rule_ids)
        for asset in (*template.variants, *template.task_scope, template.entry_point.asset_id):
            assert asset.split(":", 1)[0] in {"file", "table", "api"}


@pytest.mark.parametrize(
    "value",
    [
        "00000000-0000-0000-0000-000000000000",
        "event:1234",
        "session:abcd",
        "cat ~/.ssh/id_rsa",
        "file:/sensitive/../../etc/shadow",
    ],
)
def test_template_target_cannot_be_an_attack_identifier(tmp_path: Path, value: str) -> None:
    root = copy_config(tmp_path)
    relative = "scenarios/template_library_v1/T-02.yaml"
    mutate(root, relative, lambda d: d["parameters"]["target_asset"].update(allowed=[value]))
    with pytest.raises(ConfigValidationError):
        load_config(root)


# --- secrets ---------------------------------------------------------------------------------


def _tracked_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        capture_output=True,
        check=True,
        cwd=REPO_ROOT,
    ).stdout.decode()
    return [REPO_ROOT / name for name in out.split("\0") if name]


def test_fixture_credentials_never_leave_their_asset() -> None:
    """FR-004c part 1: no fixture credential appears anywhere else in the repository,
    including (from P3) the Cowrie configuration."""
    bundle = load_config(CONFIG_ROOT)
    owners: dict[str, Path] = {}
    for fixture_set in bundle.fixture_sets.values():
        for asset in fixture_set.manifest.model.assets:
            source = (
                fixture_set.files[asset.asset_id].source
                if asset.kind == "file"
                else fixture_set.tables[asset.asset_id].source
            )
            for credential in asset.fabricated_credentials:
                owners[credential] = CONFIG_ROOT / source
    assert owners
    manifest = CONFIG_ROOT / "fixtures" / "fixture_set_v1" / "manifest.yaml"
    for path in _tracked_files():
        if not path.is_file() or path == manifest:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for credential, owner in owners.items():
            if credential in text:
                assert path == owner or path.name in {
                    "test_artifact_validation.py",
                    "test_config_security.py",
                }, f"{credential} leaked into {path.relative_to(REPO_ROOT)}"


def test_fixture_credentials_are_marked_fabricated() -> None:
    bundle = load_config(CONFIG_ROOT)
    for fixture_set in bundle.fixture_sets.values():
        for asset in fixture_set.manifest.model.assets:
            for credential in asset.fabricated_credentials:
                assert credential.startswith("aitlfx-")


def test_llm_config_holds_no_credential_or_endpoint() -> None:
    for path in (CONFIG_ROOT / "agents").glob("*.yaml"):
        text = path.read_text().lower()
        for marker in ("api_key", "apikey", "secret", "token:", "base_url", "://", "password"):
            assert marker not in text, (path.name, marker)
