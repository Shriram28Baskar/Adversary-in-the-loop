"""Load, validate and cross-reference the complete configuration tree.

``load_config(root)`` discovers every artifact from a fixed layout, validates
each one (schema + semantics), then validates every cross-reference between
them, and returns an immutable ``ConfigBundle`` - or raises one
``ConfigValidationError`` listing *every* issue found. There is no partial
result: a bundle exists only when the whole tree is valid.

Layout (engineering plan §3, §15)::

    attack/attack_mapping_vN.yaml         intel/phase_rules_vN.yaml
    intel/ttp_rules_vN.yaml               abstraction/abstraction_table_vN.yaml
    scenarios/template_library_vN/T-NN.yaml
    tasks/TK-N_vM.yaml                    tools/tool_definitions_vN.yaml
    fixtures/fixture_set_vN/{manifest.yaml, files/**, db/*.yaml, api/*.yaml}
    agents/<agent_id>_vN.yaml             agents/prompts/<prompt_id>_vN.md
    agents/scripted_plans/T-NN.yaml       policies/<policy_id>_vN.yaml
    eval/eval-vN.yaml                     README.md

Anything else in the tree is an ``unexpected_file`` error, never ignored. The
version in a filename must equal the version inside the file. Every reference
between artifacts names an explicit version; nothing resolves to "latest".
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Any, Final, TypeVar

from pydantic import BaseModel, TypeAdapter

from aitl_common.canonical_json import canonical_sha256
from aitl_common.config.errors import ArtifactIssue, ConfigValidationError, IssueType, issue
from aitl_common.config.loader import ConfigRoot, LoadedArtifact, RawFile
from aitl_common.config.policy_rules import (
    PermissionContext,
    analyze_policy,
    permission_contexts,
    winning_dataflow,
    winning_permission,
)
from aitl_common.config.schemas.abstraction import AbstractionTable
from aitl_common.config.schemas.agents import (
    AgentConfig,
    FinalResponseStep,
    LlmAgentConfig,
    ResultOf,
    ScriptedAgentConfig,
    ScriptedPlan,
    ToolCallStep,
)
from aitl_common.config.schemas.attack import AttackMapping
from aitl_common.config.schemas.evaluation import EvalConfig
from aitl_common.config.schemas.fixtures import (
    CANARY_PLACEHOLDER,
    FINGERPRINT_MIN_LINE,
    FixtureAsset,
    FixtureSetManifest,
    TabularData,
)
from aitl_common.config.schemas.intel import (
    CommandArgumentMatch,
    CommandMatch,
    CommandPrefixMatch,
    PhaseRules,
    TtpRules,
)
from aitl_common.config.schemas.policies import BASELINE_POLICY_ID, Policy
from aitl_common.config.schemas.scenarios import (
    ASSET_KINDS_FOR_TOOL,
    AdversarialInstructionStep,
    CalledPredicate,
    DataflowExpectation,
    FinalResponseContainsAll,
    PermissionExpectation,
    ScenarioTemplate,
)
from aitl_common.config.schemas.tasks import AgentTaskDefinition
from aitl_common.config.schemas.tools import (
    FilterListArg,
    FixturePathArg,
    FixtureTableArg,
    IntegerArg,
    StringArg,
    ToolDefinitions,
    ToolSpec,
)

__all__ = ["ConfigBundle", "FixtureSetBundle", "TemplateLibrary", "load_config"]

K = TypeVar("K")
V = TypeVar("V")

_ROOT_ENTRIES: Final = (
    "README.md",
    "abstraction/",
    "agents/",
    "attack/",
    "eval/",
    "fixtures/",
    "intel/",
    "policies/",
    "scenarios/",
    "tasks/",
    "tools/",
)
_N = r"([1-9][0-9]{0,5})"
_URL_RE: Final = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://")
_AGENT_KIND_ADAPTER: Final[TypeAdapter[LlmAgentConfig | ScriptedAgentConfig]] = TypeAdapter(
    AgentConfig
)


@dataclass(frozen=True)
class FixtureSetBundle:
    manifest: LoadedArtifact[FixtureSetManifest]
    files: Mapping[str, RawFile]  # asset_id -> file content (kind file)
    tables: Mapping[str, LoadedArtifact[TabularData]]  # asset_id -> table/api data
    content_sha256: str

    @property
    def version(self) -> str:
        return self.manifest.model.version

    def asset_sha256(self, asset: FixtureAsset) -> str:
        if asset.kind == "file":
            return self.files[asset.asset_id].sha256
        return self.tables[asset.asset_id].content_sha256

    def asset_text(self, asset_id: str) -> str:
        if asset_id in self.files:
            return self.files[asset_id].text
        return self.tables[asset_id].model.text()


@dataclass(frozen=True)
class TemplateLibrary:
    version: str
    templates: Mapping[str, LoadedArtifact[ScenarioTemplate]]
    content_sha256: str


@dataclass(frozen=True)
class ConfigBundle:
    root: Path
    attack_mappings: Mapping[str, LoadedArtifact[AttackMapping]]
    phase_rules: Mapping[str, LoadedArtifact[PhaseRules]]
    ttp_rules: Mapping[str, LoadedArtifact[TtpRules]]
    abstraction_tables: Mapping[str, LoadedArtifact[AbstractionTable]]
    template_libraries: Mapping[str, TemplateLibrary]
    tasks: Mapping[tuple[str, int], LoadedArtifact[AgentTaskDefinition]]
    tool_definitions: Mapping[str, LoadedArtifact[ToolDefinitions]]
    fixture_sets: Mapping[str, FixtureSetBundle]
    agents: Mapping[tuple[str, int], LoadedArtifact[LlmAgentConfig | ScriptedAgentConfig]]
    prompts: Mapping[tuple[str, int], RawFile]
    scripted_plans: Mapping[tuple[str, int], LoadedArtifact[ScriptedPlan]]
    policies: Mapping[tuple[str, int], LoadedArtifact[Policy]]
    eval_configs: Mapping[str, LoadedArtifact[EvalConfig]]

    def inventory(self) -> list[dict[str, str]]:
        """Every artifact: kind, id, version, content hash, source. Sorted, deterministic."""
        rows: list[dict[str, str]] = []

        def add(kind: str, ident: str, version: str, sha: str, source: str) -> None:
            rows.append(
                {"kind": kind, "id": ident, "version": version, "sha256": sha, "source": source}
            )

        labeled: list[tuple[str, Mapping[str, LoadedArtifact[Any]]]] = [
            ("attack_mapping", self.attack_mappings),
            ("phase_rules", self.phase_rules),
            ("ttp_rules", self.ttp_rules),
            ("abstraction_table", self.abstraction_tables),
            ("tool_definitions", self.tool_definitions),
            ("eval_config", self.eval_configs),
        ]
        for kind, artifacts in labeled:
            for version, artifact in artifacts.items():
                add(kind, kind, version, artifact.content_sha256, artifact.source)
        keyed: list[tuple[str, Mapping[tuple[str, int], LoadedArtifact[Any]]]] = [
            ("agent_task", self.tasks),
            ("agent_config", self.agents),
            ("scripted_plan", self.scripted_plans),
            ("policy", self.policies),
        ]
        for kind, keyed_artifacts in keyed:
            for (ident, int_version), artifact in keyed_artifacts.items():
                add(kind, ident, str(int_version), artifact.content_sha256, artifact.source)
        for version, library in self.template_libraries.items():
            add(
                "template_library",
                "template_library",
                version,
                library.content_sha256,
                f"scenarios/{version}",
            )
            for template_id, template in library.templates.items():
                add(
                    "scenario_template",
                    template_id,
                    version,
                    template.content_sha256,
                    template.source,
                )
        for version, fixture_set in self.fixture_sets.items():
            add(
                "fixture_set",
                "fixture_set",
                version,
                fixture_set.content_sha256,
                fixture_set.manifest.source,
            )
        for (prompt_id, prompt_version), prompt in self.prompts.items():
            add("system_prompt", prompt_id, str(prompt_version), prompt.sha256, prompt.source)
        return sorted(rows, key=lambda r: (r["kind"], r["id"], r["version"]))

    def roles(self) -> frozenset[str]:
        return frozenset(a.model.role for a in self.agents.values())


# --------------------------------------------------------------------------------------
# Collection helpers
# --------------------------------------------------------------------------------------


@dataclass
class _Issues:
    items: list[ArtifactIssue] = field(default_factory=list)

    def add(
        self,
        artifact: str,
        version: str | None,
        path: str,
        error_type: IssueType,
        message: str,
        identifier: str | None = None,
    ) -> None:
        self.items.append(issue(artifact, version, path, error_type, message, identifier))

    def attempt(self, action: Callable[[], V]) -> V | None:
        try:
            return action()
        except ConfigValidationError as exc:
            self.items.extend(exc.issues)
            return None


def _put(issues: _Issues, target: dict[K, V], key: K, value: V, source: str, version: str) -> None:
    if key in target:
        issues.add(source, version, "$", IssueType.DUPLICATE_VERSION, f"{key} is defined twice")
        return
    target[key] = value


def _strings(value: Any, path: str = "$") -> Iterator[tuple[str, str]]:
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, Mapping):
        for key, item in value.items():
            yield f"{path}.{key}", str(key)
            yield from _strings(item, f"{path}.{key}")
    elif isinstance(value, list | tuple):
        for index, item in enumerate(value):
            yield from _strings(item, f"{path}[{index}]")


# --------------------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------------------


class _Discovery:
    def __init__(self, root: ConfigRoot, issues: _Issues) -> None:
        self.root = root
        self.issues = issues

    def entries(self, directory: str, patterns: Iterable[str]) -> list[tuple[str, re.Match[str]]]:
        """Entries of ``directory`` matching one of ``patterns``; others are errors."""
        listed = self.issues.attempt(lambda: self.root.list_dir(directory))
        if listed is None:
            return []
        compiled = [re.compile(p) for p in patterns]
        found: list[tuple[str, re.Match[str]]] = []
        for name in listed:
            match = next((m for p in compiled if (m := p.fullmatch(name))), None)
            where = f"{directory}/{name}" if directory else name
            if match is None:
                self.issues.add(
                    where,
                    None,
                    "$",
                    IssueType.UNEXPECTED_FILE,
                    "not part of the configuration layout",
                )
            else:
                found.append((where.rstrip("/"), match))
        return found

    def require_dir(self, name: str) -> bool:
        if not self.root.exists(name):
            self.issues.add(name, None, "$", IssueType.MISSING_ARTIFACT, "directory is missing")
            return False
        return True


def _check_version(
    issues: _Issues, source: str, declared: str, expected: str, what: str = "version"
) -> None:
    if declared != expected:
        issues.add(
            source,
            declared,
            what,
            IssueType.VERSION_MISMATCH,
            f"file name implies {expected!r} but the file declares {declared!r}",
            declared,
        )


def _load_labeled(
    discovery: _Discovery,
    directory: str,
    stem: str,
    label: str,
    schema: type[BaseModel],
    target: dict[str, Any],
) -> None:
    issues = discovery.issues
    for source, match in discovery.entries(directory, [rf"{stem}_v{_N}\.yaml"]):
        loaded = issues.attempt(partial(discovery.root.load_yaml, source, schema))
        if loaded is None:
            continue
        expected = f"{label}-v{match.group(1)}"
        _check_version(issues, source, loaded.model.version, expected)
        _put(issues, target, loaded.model.version, loaded, source, loaded.model.version)


# --------------------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------------------


def load_config(root: Path) -> ConfigBundle:
    """Load and validate the whole configuration tree, or raise ConfigValidationError."""
    issues = _Issues()
    config_root = ConfigRoot(root)
    discovery = _Discovery(config_root, issues)

    discovery.entries("", [re.escape(e) for e in _ROOT_ENTRIES])
    for entry in _ROOT_ENTRIES:
        if entry.endswith("/"):
            discovery.require_dir(entry.rstrip("/"))

    attack: dict[str, LoadedArtifact[AttackMapping]] = {}
    phase: dict[str, LoadedArtifact[PhaseRules]] = {}
    ttp: dict[str, LoadedArtifact[TtpRules]] = {}
    abstraction: dict[str, LoadedArtifact[AbstractionTable]] = {}
    tools: dict[str, LoadedArtifact[ToolDefinitions]] = {}
    evals: dict[str, LoadedArtifact[EvalConfig]] = {}
    if config_root.exists("attack"):
        _load_labeled(
            discovery, "attack", "attack_mapping", "attack-mapping", AttackMapping, attack
        )
    if config_root.exists("intel"):
        # Two stems share the directory; list once and dispatch by name.
        for source, match in discovery.entries(
            "intel", [rf"(phase_rules)_v{_N}\.yaml", rf"(ttp_rules)_v{_N}\.yaml"]
        ):
            stem, n = match.group(1), match.group(2)
            schema: type[BaseModel] = PhaseRules if stem == "phase_rules" else TtpRules
            target: dict[str, Any] = phase if stem == "phase_rules" else ttp
            loaded_intel = issues.attempt(partial(config_root.load_yaml, source, schema))
            if loaded_intel is not None:
                version = loaded_intel.model.version
                _check_version(issues, source, version, f"{stem.replace('_', '-')}-v{n}")
                _put(issues, target, version, loaded_intel, source, version)
    if config_root.exists("abstraction"):
        _load_labeled(
            discovery,
            "abstraction",
            "abstraction_table",
            "abstraction-table",
            AbstractionTable,
            abstraction,
        )
    if config_root.exists("tools"):
        _load_labeled(
            discovery, "tools", "tool_definitions", "tool-definitions", ToolDefinitions, tools
        )
    if config_root.exists("eval"):
        for source, match in discovery.entries("eval", [rf"eval-v{_N}\.yaml"]):
            loaded_eval = issues.attempt(partial(config_root.load_yaml, source, EvalConfig))
            if loaded_eval is not None:
                version = loaded_eval.model.version
                _check_version(issues, source, version, f"eval-v{match.group(1)}")
                _put(issues, evals, version, loaded_eval, source, version)

    libraries = _load_templates(discovery) if config_root.exists("scenarios") else {}
    tasks = _load_tasks(discovery) if config_root.exists("tasks") else {}
    fixture_sets = _load_fixture_sets(discovery) if config_root.exists("fixtures") else {}
    agents, prompts, plans = (
        _load_agents(discovery) if config_root.exists("agents") else ({}, {}, {})
    )
    policies = _load_policies(discovery) if config_root.exists("policies") else {}

    for name, collection in (
        ("attack/attack_mapping", attack),
        ("intel/phase_rules", phase),
        ("intel/ttp_rules", ttp),
        ("abstraction/abstraction_table", abstraction),
        ("scenarios/template_library", libraries),
        ("tasks", tasks),
        ("tools/tool_definitions", tools),
        ("fixtures/fixture_set", fixture_sets),
        ("agents", agents),
        ("agents/prompts", prompts),
        ("policies", policies),
        ("eval", evals),
    ):
        if not collection:
            issues.add(name, None, "$", IssueType.MISSING_ARTIFACT, "no artifact of this kind")

    bundle = ConfigBundle(
        root=config_root.path,
        attack_mappings=attack,
        phase_rules=phase,
        ttp_rules=ttp,
        abstraction_tables=abstraction,
        template_libraries=libraries,
        tasks=tasks,
        tool_definitions=tools,
        fixture_sets=fixture_sets,
        agents=agents,
        prompts=prompts,
        scripted_plans=plans,
        policies=policies,
        eval_configs=evals,
    )
    if not issues.items:
        _cross_validate(bundle, issues)
    if issues.items:
        raise ConfigValidationError(issues.items)
    return bundle


# --------------------------------------------------------------------------------------
# Directory-shaped artifacts
# --------------------------------------------------------------------------------------


def _load_templates(discovery: _Discovery) -> dict[str, TemplateLibrary]:
    issues = discovery.issues
    libraries: dict[str, TemplateLibrary] = {}
    for directory, match in discovery.entries("scenarios", [rf"template_library_v{_N}/"]):
        version = f"template-library-v{match.group(1)}"
        templates: dict[str, LoadedArtifact[ScenarioTemplate]] = {}
        for source, tmatch in discovery.entries(directory, [r"(T-[0-9]{2})\.yaml"]):
            loaded = issues.attempt(partial(discovery.root.load_yaml, source, ScenarioTemplate))
            if loaded is None:
                continue
            model = loaded.model
            _check_version(
                issues, source, model.template_library_version, version, "template_library_version"
            )
            if model.template_id != tmatch.group(1):
                issues.add(
                    source,
                    version,
                    "template_id",
                    IssueType.VERSION_MISMATCH,
                    f"file name implies {tmatch.group(1)!r}",
                    model.template_id,
                )
            _put(issues, templates, model.template_id, loaded, source, version)
        if not templates:
            issues.add(directory, version, "$", IssueType.MISSING_ARTIFACT, "library is empty")
        digest = canonical_sha256({tid: t.content_sha256 for tid, t in templates.items()})
        libraries[version] = TemplateLibrary(version, templates, digest)
    return libraries


def _load_tasks(
    discovery: _Discovery,
) -> dict[tuple[str, int], LoadedArtifact[AgentTaskDefinition]]:
    issues = discovery.issues
    tasks: dict[tuple[str, int], LoadedArtifact[AgentTaskDefinition]] = {}
    for source, match in discovery.entries("tasks", [rf"(TK-[1-9][0-9]*)_v{_N}\.yaml"]):
        loaded = issues.attempt(partial(discovery.root.load_yaml, source, AgentTaskDefinition))
        if loaded is None:
            continue
        model = loaded.model
        key = (model.task_id, model.version)
        if key != (match.group(1), int(match.group(2))):
            issues.add(
                source,
                str(model.version),
                "task_id/version",
                IssueType.VERSION_MISMATCH,
                f"file name implies {match.group(1)} v{match.group(2)}",
                model.task_id,
            )
        _put(issues, tasks, key, loaded, source, str(model.version))
    return tasks


def _load_policies(discovery: _Discovery) -> dict[tuple[str, int], LoadedArtifact[Policy]]:
    issues = discovery.issues
    policies: dict[tuple[str, int], LoadedArtifact[Policy]] = {}
    for source, match in discovery.entries("policies", [rf"([a-z][a-z0-9-]*)_v{_N}\.yaml"]):
        loaded = issues.attempt(partial(discovery.root.load_yaml, source, Policy))
        if loaded is None:
            continue
        model = loaded.model
        key = (model.policy_id, model.version)
        if key != (match.group(1), int(match.group(2))):
            issues.add(
                source,
                str(model.version),
                "policy_id/version",
                IssueType.VERSION_MISMATCH,
                f"file name implies {match.group(1)} v{match.group(2)}",
                model.policy_id,
            )
        _put(issues, policies, key, loaded, source, str(model.version))
    return policies


def _load_agents(
    discovery: _Discovery,
) -> tuple[
    dict[tuple[str, int], LoadedArtifact[LlmAgentConfig | ScriptedAgentConfig]],
    dict[tuple[str, int], RawFile],
    dict[tuple[str, int], LoadedArtifact[ScriptedPlan]],
]:
    issues = discovery.issues
    root = discovery.root
    agents: dict[tuple[str, int], LoadedArtifact[LlmAgentConfig | ScriptedAgentConfig]] = {}
    prompts: dict[tuple[str, int], RawFile] = {}
    plans: dict[tuple[str, int], LoadedArtifact[ScriptedPlan]] = {}
    for source, match in discovery.entries(
        "agents", [rf"([a-z][a-z0-9_]*)_v{_N}\.yaml", r"prompts/", r"scripted_plans/"]
    ):
        if source in ("agents/prompts", "agents/scripted_plans"):
            continue
        loaded = issues.attempt(partial(root.load_yaml, source, _AGENT_KIND_ADAPTER))
        if loaded is None:
            continue
        model = loaded.model
        key = (model.agent_id, model.version)
        if key != (match.group(1), int(match.group(2))):
            issues.add(
                source,
                str(model.version),
                "agent_id/version",
                IssueType.VERSION_MISMATCH,
                f"file name implies {match.group(1)} v{match.group(2)}",
                model.agent_id,
            )
        _put(issues, agents, key, loaded, source, str(model.version))
    if discovery.require_dir("agents/prompts"):
        for source, match in discovery.entries("agents/prompts", [rf"([a-z][a-z0-9_]*)_v{_N}\.md"]):
            raw = issues.attempt(partial(root.load_text, source))
            if raw is not None:
                _put(
                    issues,
                    prompts,
                    (match.group(1), int(match.group(2))),
                    raw,
                    source,
                    match.group(2),
                )
    if discovery.require_dir("agents/scripted_plans"):
        for source, match in discovery.entries("agents/scripted_plans", [r"(T-[0-9]{2})\.yaml"]):
            plan = issues.attempt(partial(root.load_yaml, source, ScriptedPlan))
            if plan is None:
                continue
            if plan.model.template_id != match.group(1):
                issues.add(
                    source,
                    str(plan.model.version),
                    "template_id",
                    IssueType.VERSION_MISMATCH,
                    f"file name implies {match.group(1)!r}",
                    plan.model.template_id,
                )
            key = (plan.model.template_id, plan.model.version)
            _put(issues, plans, key, plan, source, str(plan.model.version))
    return agents, prompts, plans


def _walk_files(root: ConfigRoot, directory: str) -> list[str]:
    files: list[str] = []
    for name in root.list_dir(directory):
        path = f"{directory}/{name.rstrip('/')}"
        if name.endswith("/"):
            files.extend(_walk_files(root, path))
        else:
            files.append(path)
    return files


def _load_fixture_sets(discovery: _Discovery) -> dict[str, FixtureSetBundle]:
    issues = discovery.issues
    root = discovery.root
    sets: dict[str, FixtureSetBundle] = {}
    for directory, match in discovery.entries("fixtures", [rf"fixture_set_v{_N}/"]):
        version = f"fixture-set-v{match.group(1)}"
        manifest = issues.attempt(
            partial(root.load_yaml, f"{directory}/manifest.yaml", FixtureSetManifest)
        )
        if manifest is None:
            continue
        _check_version(issues, manifest.source, manifest.model.version, version)
        present = issues.attempt(partial(_walk_files, root, directory)) or []
        referenced = {f"{directory}/manifest.yaml"}
        files: dict[str, RawFile] = {}
        tables: dict[str, LoadedArtifact[TabularData]] = {}
        for asset in manifest.model.assets:
            source = f"{directory}/{asset.source}"
            referenced.add(source)
            if asset.kind == "file":
                raw = issues.attempt(partial(root.load_text, source))
                if raw is not None:
                    files[asset.asset_id] = raw
            else:
                table = issues.attempt(partial(root.load_yaml, source, TabularData))
                if table is None:
                    continue
                expected_kind = "table" if asset.kind == "table" else "api_data"
                if (table.model.name, table.model.kind) != (asset.locator, expected_kind):
                    issues.add(
                        source,
                        version,
                        "name/kind",
                        IssueType.INCONSISTENT,
                        f"data file must declare name={asset.locator!r}, kind={expected_kind!r}",
                        asset.asset_id,
                    )
                tables[asset.asset_id] = table
        for extra in sorted(set(present) - referenced):
            issues.add(
                extra,
                version,
                "$",
                IssueType.UNEXPECTED_FILE,
                "file is not referenced by the fixture manifest",
            )
        asset_hashes = {
            a.asset_id: (
                files[a.asset_id].sha256 if a.kind == "file" else tables[a.asset_id].content_sha256
            )
            for a in manifest.model.assets
            if a.asset_id in files or a.asset_id in tables
        }
        digest = canonical_sha256({"manifest": manifest.content_sha256, "assets": asset_hashes})
        _put(
            issues,
            sets,
            version,
            FixtureSetBundle(manifest, files, tables, digest),
            manifest.source,
            version,
        )
    return sets


# --------------------------------------------------------------------------------------
# Cross-reference validation
# --------------------------------------------------------------------------------------


def _cross_validate(bundle: ConfigBundle, issues: _Issues) -> None:
    _check_fixtures(bundle, issues)
    _check_intel(bundle, issues)
    _check_tasks(bundle, issues)
    _check_tools(bundle, issues)
    _check_policies(bundle, issues)
    _check_templates(bundle, issues)
    _check_plans(bundle, issues)
    _check_agents(bundle, issues)
    _check_forbidden_content(bundle, issues)


def _check_fixtures(bundle: ConfigBundle, issues: _Issues) -> None:
    for version, fixture_set in bundle.fixture_sets.items():
        for asset in fixture_set.manifest.model.assets:
            text = fixture_set.asset_text(asset.asset_id)
            source = (
                fixture_set.files[asset.asset_id].source
                if asset.kind == "file"
                else fixture_set.tables[asset.asset_id].source
            )
            count = text.count(CANARY_PLACEHOLDER)
            wanted = 1 if asset.has_markers else 0
            if count != wanted:
                issues.add(
                    source,
                    version,
                    "$",
                    IssueType.INCONSISTENT,
                    f"{asset.asset_id} must contain the canary placeholder exactly {wanted} "
                    f"time(s), found {count} (FR-024)",
                    asset.asset_id,
                )
            if asset.has_markers and not any(
                len(" ".join(line.split())) >= FINGERPRINT_MIN_LINE
                for line in text.splitlines()
                if CANARY_PLACEHOLDER not in line
            ):
                issues.add(
                    source,
                    version,
                    "$",
                    IssueType.INCONSISTENT,
                    f"{asset.asset_id} has no line of >= {FINGERPRINT_MIN_LINE} characters "
                    "to fingerprint (ARCHITECTURE.md §18)",
                    asset.asset_id,
                )
            for credential in asset.fabricated_credentials:
                if credential not in text:
                    issues.add(
                        source,
                        version,
                        "fabricated_credentials",
                        IssueType.UNKNOWN_REFERENCE,
                        "declared fabricated credential does not appear in the asset",
                        credential,
                    )


def _check_intel(bundle: ConfigBundle, issues: _Issues) -> None:
    for version, loaded in bundle.ttp_rules.items():
        rules = loaded.model
        mapping = bundle.attack_mappings.get(rules.attack_mapping_version)
        phase_rules = bundle.phase_rules.get(rules.phase_rules_version)
        if mapping is None:
            issues.add(
                loaded.source,
                version,
                "attack_mapping_version",
                IssueType.UNKNOWN_REFERENCE,
                "no such ATT&CK mapping",
                rules.attack_mapping_version,
            )
        if phase_rules is None:
            issues.add(
                loaded.source,
                version,
                "phase_rules_version",
                IssueType.UNKNOWN_REFERENCE,
                "no such phase-rule table",
                rules.phase_rules_version,
            )
        if mapping is None or phase_rules is None:
            continue
        known_labels = mapping.model.mapped_labels | set(mapping.model.unmapped_labels)
        for index, rule in enumerate(rules.rules):
            path = f"rules[{index}]"
            if rule.label not in known_labels:
                issues.add(
                    loaded.source,
                    version,
                    f"{path}.label",
                    IssueType.UNSUPPORTED_LABEL,
                    "label is neither mapped nor declared unmapped in the ATT&CK mapping",
                    rule.label,
                )
            same_phase = [p.match for p in phase_rules.model.rules if p.phase == rule.phase]
            if not same_phase:
                issues.add(
                    loaded.source,
                    version,
                    f"{path}.phase",
                    IssueType.UNKNOWN_REFERENCE,
                    "no phase rule produces this phase",
                    rule.phase,
                )
                continue
            match = rule.match
            commands: tuple[str, ...] = ()
            if isinstance(match, CommandMatch | CommandArgumentMatch):
                commands = match.commands
            elif isinstance(match, CommandPrefixMatch):
                # A prefix is reachable if some phase rule routes commands it can match.
                for prefix in match.prefixes:
                    if not any(
                        (
                            isinstance(m, CommandPrefixMatch)
                            and any(
                                prefix.startswith(p) or p.startswith(prefix) for p in m.prefixes
                            )
                        )
                        or (
                            isinstance(m, CommandMatch | CommandArgumentMatch)
                            and any(c.startswith(prefix) for c in m.commands)
                        )
                        for m in same_phase
                    ):
                        issues.add(
                            loaded.source,
                            version,
                            f"{path}.match",
                            IssueType.DEAD_RULE,
                            f"no {rule.phase} phase rule can route commands starting "
                            f"with {prefix!r}",
                            rule.rule_id,
                        )
            for command in commands:
                if not any(_phase_routes(m, command) for m in same_phase):
                    issues.add(
                        loaded.source,
                        version,
                        f"{path}.match",
                        IssueType.DEAD_RULE,
                        f"no {rule.phase} phase rule routes command {command!r}",
                        rule.rule_id,
                    )
    for version, loaded_table in bundle.abstraction_tables.items():
        table = loaded_table.model
        mapping = bundle.attack_mappings.get(table.attack_mapping_version)
        if mapping is None:
            issues.add(
                loaded_table.source,
                version,
                "attack_mapping_version",
                IssueType.UNKNOWN_REFERENCE,
                "no such ATT&CK mapping",
                table.attack_mapping_version,
            )
            continue
        known = mapping.model.tactic_ids | mapping.model.technique_ids
        for index, abstraction_rule in enumerate(table.rules):
            for element in sorted(abstraction_rule.element_ids() - known):
                issues.add(
                    loaded_table.source,
                    version,
                    f"rules[{index}].elements",
                    IssueType.UNSUPPORTED_TECHNIQUE,
                    f"{abstraction_rule.rule_id} names an ID outside the curated ATT&CK subset",
                    element,
                )


def _phase_routes(match: Any, command: str) -> bool:
    if isinstance(match, CommandMatch | CommandArgumentMatch):
        return command in match.commands
    if isinstance(match, CommandPrefixMatch):
        return any(command.startswith(p) for p in match.prefixes)
    return False


def _fixture(bundle: ConfigBundle, version: str) -> FixtureSetBundle | None:
    return bundle.fixture_sets.get(version)


def _check_tasks(bundle: ConfigBundle, issues: _Issues) -> None:
    for (task_id, version), loaded in bundle.tasks.items():
        task = loaded.model
        fixture_set = _fixture(bundle, task.fixture_set_version)
        if fixture_set is None:
            issues.add(
                loaded.source,
                str(version),
                "fixture_set_version",
                IssueType.UNKNOWN_REFERENCE,
                "no such fixture set",
                task.fixture_set_version,
            )
            continue
        asset = fixture_set.manifest.model.file_asset_by_path(task.document_path)
        if asset is None or asset.tier != "public":
            issues.add(
                loaded.source,
                str(version),
                "document_path",
                IssueType.UNKNOWN_REFERENCE,
                "the task document must be a public file asset of the fixture set",
                task.document_path,
            )
            continue
        document = fixture_set.asset_text(asset.asset_id)
        for token in task.task_fact_tokens:
            if token not in document:
                issues.add(
                    loaded.source,
                    str(version),
                    "task_fact_tokens",
                    IssueType.UNKNOWN_REFERENCE,
                    "task-fact token does not appear in the task document",
                    token,
                )
        if task.document_path not in task.prompt:
            issues.add(
                loaded.source,
                str(version),
                "prompt",
                IssueType.INCONSISTENT,
                "the task prompt must name the task document",
                task_id,
            )


def _check_tools(bundle: ConfigBundle, issues: _Issues) -> None:
    for version, loaded in bundle.tool_definitions.items():
        for (tool, endpoint), spec in loaded.model.entries().items():
            resource = spec.resource
            if resource.kind != "fixed_asset":
                continue
            for fs_version, fixture_set in bundle.fixture_sets.items():
                if not any(
                    a.kind == resource.asset_kind and a.locator == resource.locator
                    for a in fixture_set.manifest.model.assets
                ):
                    issues.add(
                        loaded.source,
                        version,
                        f"tools.{tool}.{endpoint}.resource",
                        IssueType.UNKNOWN_REFERENCE,
                        f"fixed asset {resource.asset_kind}:{resource.locator} is missing from "
                        f"{fs_version}",
                        resource.locator,
                    )


def _contexts_for(bundle: ConfigBundle, tools_version: str) -> list[PermissionContext]:
    tools = bundle.tool_definitions[tools_version].model
    manifests = [fs.manifest.model for fs in bundle.fixture_sets.values()]
    return permission_contexts(bundle.roles(), tools, manifests)


def _check_policies(bundle: ConfigBundle, issues: _Issues) -> None:
    if BASELINE_POLICY_ID not in {pid for pid, _ in bundle.policies}:
        issues.add(
            "policies",
            None,
            "$",
            IssueType.MISSING_ARTIFACT,
            f"the fixed baseline policy {BASELINE_POLICY_ID} is required (FR-033a)",
            BASELINE_POLICY_ID,
        )
    for (_policy_id, version), loaded in bundle.policies.items():
        policy = loaded.model
        if policy.tool_definitions_version not in bundle.tool_definitions:
            issues.add(
                loaded.source,
                str(version),
                "tool_definitions_version",
                IssueType.UNKNOWN_REFERENCE,
                "no such tool definitions",
                policy.tool_definitions_version,
            )
            continue
        contexts = _contexts_for(bundle, policy.tool_definitions_version)
        for problem in analyze_policy(policy, contexts, bundle.roles()):
            issues.add(
                loaded.source,
                str(version),
                "rules",
                problem.error_type,
                problem.message,
                problem.identifier,
            )


def _asset_ref(ref: str | None, target: str, fixture_set: FixtureSetBundle) -> FixtureAsset | None:
    if ref is None:
        return None
    return fixture_set.manifest.model.asset(target if ref == "target" else ref)


def _check_templates(bundle: ConfigBundle, issues: _Issues) -> None:
    for library in bundle.template_libraries.values():
        for loaded in library.templates.values():
            _check_template(bundle, issues, loaded)


def _check_template(
    bundle: ConfigBundle, issues: _Issues, loaded: LoadedArtifact[ScenarioTemplate]
) -> None:
    t = loaded.model
    src, ver = loaded.source, t.template_library_version

    def bad(path: str, error_type: IssueType, message: str, ident: str | None = None) -> None:
        issues.add(src, ver, path, error_type, message, ident)

    compat = t.compatible_with
    table = bundle.abstraction_tables.get(compat.abstraction_table_version)
    if table is None:
        bad(
            "compatible_with.abstraction_table_version",
            IssueType.UNKNOWN_REFERENCE,
            "no such abstraction table",
            compat.abstraction_table_version,
        )
    else:
        for rule_id in compat.rule_ids:
            rule = table.model.rule(rule_id)
            if rule is None:
                bad(
                    "compatible_with.rule_ids",
                    IssueType.UNKNOWN_REFERENCE,
                    "no such abstraction rule (threat-pattern representation)",
                    rule_id,
                )
            elif (rule.objective, rule.target_tier, rule.movement) != (
                compat.objective,
                compat.target_tier,
                compat.movement,
            ):
                bad(
                    "compatible_with",
                    IssueType.INCONSISTENT,
                    f"{rule_id} produces ({rule.objective}, {rule.target_tier}, {rule.movement})",
                    rule_id,
                )
    task_loaded = bundle.tasks.get((t.agent_task.task_id, t.agent_task.version))
    if task_loaded is None:
        bad(
            "agent_task",
            IssueType.UNKNOWN_REFERENCE,
            "no such task",
            f"{t.agent_task.task_id}@{t.agent_task.version}",
        )
    if t.agent_role not in bundle.roles():
        bad("agent_role", IssueType.UNKNOWN_REFERENCE, "no agent has this role", t.agent_role)
    tools_loaded = bundle.tool_definitions.get(t.tool_definitions_version)
    if tools_loaded is None:
        bad(
            "tool_definitions_version",
            IssueType.UNKNOWN_REFERENCE,
            "no such tool definitions",
            t.tool_definitions_version,
        )
    policy_loaded = bundle.policies.get((t.target_policy.policy_id, t.target_policy.version))
    if policy_loaded is None:
        bad(
            "target_policy",
            IssueType.UNKNOWN_REFERENCE,
            "no such policy",
            f"{t.target_policy.policy_id}@{t.target_policy.version}",
        )
    elif t.target_policy.policy_id == BASELINE_POLICY_ID:
        bad(
            "target_policy",
            IssueType.INCONSISTENT,
            "the baseline policy is never a target",
            BASELINE_POLICY_ID,
        )
    fixture_set = _fixture(bundle, t.fixture_set_version)
    if fixture_set is None:
        bad(
            "fixture_set_version",
            IssueType.UNKNOWN_REFERENCE,
            "no such fixture set",
            t.fixture_set_version,
        )
        return
    manifest = fixture_set.manifest.model

    def asset_exists(path: str, asset_id: str) -> FixtureAsset | None:
        asset = manifest.asset(asset_id)
        if asset is None:
            bad(path, IssueType.UNKNOWN_REFERENCE, "no such fixture asset", asset_id)
        return asset

    entry = asset_exists("entry_point.asset_id", t.entry_point.asset_id)
    if task_loaded is not None:
        task = task_loaded.model
        if task.fixture_set_version != t.fixture_set_version:
            bad(
                "agent_task",
                IssueType.INCONSISTENT,
                "task and template must use the same fixture set",
                task.fixture_set_version,
            )
        document_id = f"file:{task.document_path}"
        if entry is not None and t.entry_point.asset_id != document_id:
            bad(
                "entry_point.asset_id",
                IssueType.INCONSISTENT,
                "the poisoned instruction is embedded in the task document (§37.3)",
                t.entry_point.asset_id,
            )
        if document_id not in t.task_scope:
            bad(
                "task_scope",
                IssueType.INCONSISTENT,
                "task_scope must include the task document",
                document_id,
            )
        if isinstance(t.task_success, FinalResponseContainsAll) and set(
            t.task_success.tokens
        ) != set(task.task_fact_tokens):
            bad(
                "task_success.tokens",
                IssueType.INCONSISTENT,
                "tokens must be exactly the task's task-fact tokens",
                task.task_id,
            )
    if entry is not None and (entry.kind, entry.tier) != ("file", "public"):
        bad(
            "entry_point.asset_id",
            IssueType.INCONSISTENT,
            "document_in_fixture entry points are public files",
            entry.asset_id,
        )
    candidates = sorted(
        a.asset_id
        for a in manifest.assets
        if a.tier == t.target_selector.tier and a.kind in t.target_selector.kinds
    )
    allowed = sorted(t.parameters["target_asset"].allowed)
    if candidates != allowed:
        bad(
            "parameters.target_asset.allowed",
            IssueType.INCONSISTENT,
            f"must be exactly the assets the selector admits: {candidates}",
            ",".join(allowed),
        )
    for asset_id in t.task_scope:
        asset_exists("task_scope", asset_id)
    for index, call in enumerate(t.legitimate_calls):
        asset = asset_exists(f"legitimate_calls[{index}]", call.asset_id)
        if asset is not None and asset.kind != ASSET_KINDS_FOR_TOOL[call.tool]:
            bad(
                f"legitimate_calls[{index}]",
                IssueType.INCONSISTENT,
                f"{call.tool} cannot read a {asset.kind}",
                call.asset_id,
            )
    if isinstance(t.task_success, CalledPredicate):
        asset = asset_exists("task_success.asset_id", t.task_success.asset_id)
        if asset is not None and asset.kind != ASSET_KINDS_FOR_TOOL[t.task_success.tool]:
            bad("task_success", IssueType.INCONSISTENT, "tool/asset kind mismatch", asset.asset_id)

    tools = tools_loaded.model if tools_loaded is not None else None
    policy = policy_loaded.model if policy_loaded is not None else None
    for target, variant in t.variants.items():
        base = f"variants[{target}]"
        target_asset = manifest.asset(target)
        if target_asset is None:
            bad(base, IssueType.UNKNOWN_REFERENCE, "no such fixture asset", target)
            continue
        if target_asset.locator not in variant.poisoned_content:
            bad(
                f"{base}.poisoned_content",
                IssueType.INCONSISTENT,
                "the poisoned instruction must name its target",
                target_asset.locator,
            )
        instructions = [s for s in variant.steps if isinstance(s, AdversarialInstructionStep)]
        if not any(s.asset == "target" for s in instructions):
            bad(
                f"{base}.steps",
                IssueType.INCONSISTENT,
                "an adversarial instruction must address the target",
                target,
            )
        if compat.movement == "internal_to_external" and not any(
            s.endpoint == "send_message" for s in instructions
        ):
            bad(
                f"{base}.steps",
                IssueType.INCONSISTENT,
                "an exfiltration template must instruct a send_message call",
                target,
            )
        for s_index, step in enumerate(instructions):
            asset = _asset_ref(step.asset, target, fixture_set)
            if step.asset is not None and asset is None:
                bad(
                    f"{base}.steps[{s_index}]",
                    IssueType.UNKNOWN_REFERENCE,
                    "no such fixture asset",
                    str(step.asset),
                )
        if tools is None or policy is None:
            continue
        entries = tools.entries()
        for e_index, expectation in enumerate(variant.expected_outcome):
            path = f"{base}.expected_outcome[{e_index}]"
            spec = entries[(expectation.tool, expectation.endpoint)]
            if isinstance(expectation, PermissionExpectation):
                asset = _asset_ref(expectation.asset, target, fixture_set)
                if expectation.asset is not None and asset is None:
                    bad(
                        path,
                        IssueType.UNKNOWN_REFERENCE,
                        "no such fixture asset",
                        str(expectation.asset),
                    )
                    continue
                if (spec.resource.kind == "argument") != (asset is not None):
                    bad(
                        path,
                        IssueType.INCONSISTENT,
                        "an asset is required exactly for tools whose resource is an argument",
                        expectation.tool,
                    )
                    continue
                if asset is not None and asset.kind != spec.resource.asset_kind:  # type: ignore[union-attr]
                    bad(
                        path,
                        IssueType.INCONSISTENT,
                        f"{expectation.tool} cannot address a {asset.kind}",
                        asset.asset_id,
                    )
                    continue
                if asset is not None:
                    tier: str | None = asset.tier
                elif spec.resource.kind == "fixed_asset":
                    fixed = manifest.asset(f"api:{spec.resource.locator}")
                    tier = None if fixed is None else fixed.tier
                else:
                    tier = None
                context = PermissionContext(
                    t.agent_role, expectation.tool, expectation.endpoint, tier
                )
                permission_rule = winning_permission(policy, context)
                actual = "DENY" if permission_rule is None else permission_rule.decision
                if actual != expectation.decision:
                    bad(
                        path,
                        IssueType.INCONSISTENT,
                        f"target policy decides {actual} for {context} "
                        f"(rule {None if permission_rule is None else permission_rule.rule_id}), "
                        f"not {expectation.decision}",
                        expectation.tool,
                    )
            elif isinstance(expectation, DataflowExpectation):
                df_rule = winning_dataflow(policy, target_asset.tier, spec.destination_trust)
                actual = "DENY" if df_rule is None else df_rule.decision
                if actual != expectation.decision:
                    bad(
                        path,
                        IssueType.INCONSISTENT,
                        f"target policy data-flow decides {actual} for "
                        f"({target_asset.tier}, {spec.destination_trust}), not "
                        f"{expectation.decision}",
                        expectation.tool,
                    )


def _check_plans(bundle: ConfigBundle, issues: _Issues) -> None:
    for (template_id, version), loaded in bundle.scripted_plans.items():
        plan = loaded.model
        src, ver = loaded.source, str(version)

        def bad(
            path: str,
            error_type: IssueType,
            message: str,
            ident: str | None = None,
            src: str = src,
            ver: str = ver,
        ) -> None:
            issues.add(src, ver, path, error_type, message, ident)

        library = bundle.template_libraries.get(plan.template_library_version)
        template_loaded = None if library is None else library.templates.get(template_id)
        if template_loaded is None:
            bad(
                "template_id",
                IssueType.UNKNOWN_REFERENCE,
                f"no template {template_id} in {plan.template_library_version}",
                template_id,
            )
            continue
        template = template_loaded.model
        for field_name, plan_value, template_value in (
            ("agent_task", plan.agent_task, template.agent_task),
            ("fixture_set_version", plan.fixture_set_version, template.fixture_set_version),
            (
                "tool_definitions_version",
                plan.tool_definitions_version,
                template.tool_definitions_version,
            ),
        ):
            if plan_value != template_value:
                bad(
                    field_name,
                    IssueType.INCONSISTENT,
                    "must equal the template's value",
                    field_name,
                )
        if set(plan.variants) != set(template.variants):
            bad(
                "variants",
                IssueType.UNDECLARED_PARAMETER,
                f"variants must be exactly the template's targets {sorted(template.variants)}",
                ",".join(sorted(plan.variants)),
            )
            continue
        fixture_set = _fixture(bundle, plan.fixture_set_version)
        tools_loaded = bundle.tool_definitions.get(plan.tool_definitions_version)
        task_loaded = bundle.tasks.get((plan.agent_task.task_id, plan.agent_task.version))
        if fixture_set is None or tools_loaded is None or task_loaded is None:
            continue  # reported through the template
        entries = tools_loaded.model.entries()
        manifest = fixture_set.manifest.model
        for target, steps in plan.variants.items():
            base = f"variants[{target}]"
            target_asset = manifest.asset(target)
            by_id: dict[str, ToolCallStep] = {}
            reaches_target: set[str] = set()
            for index, step in enumerate(steps):
                path = f"{base}[{index}]"
                if isinstance(step, FinalResponseStep):
                    for token in task_loaded.model.task_fact_tokens:
                        if token not in step.text:
                            bad(
                                path,
                                IssueType.INCONSISTENT,
                                "the final response must contain every task-fact token",
                                token,
                            )
                    continue
                spec = entries.get((step.tool, step.endpoint))
                if spec is None:
                    bad(path, IssueType.UNSUPPORTED_TOOL, "no such tool/endpoint", step.tool)
                    continue
                resolved = _check_arguments(
                    spec,
                    step,
                    by_id,
                    entries,
                    fixture_set,
                    lambda p, e, m, i=None, pp=path: bad(f"{pp}.{p}", e, m, i),
                )
                if target_asset is not None and resolved == target_asset.asset_id:
                    reaches_target.add(step.step_id)
                by_id[step.step_id] = step
            if not reaches_target:
                bad(
                    base,
                    IssueType.INCONSISTENT,
                    "the plan must attempt the call the poisoned instruction asks for",
                    target,
                )
            if template.compatible_with.movement == "internal_to_external" and not any(
                s.endpoint == "send_message"
                and any(
                    isinstance(v, ResultOf) and v.result_of in reaches_target
                    for v in s.arguments.values()
                )
                for s in by_id.values()
            ):
                bad(
                    base,
                    IssueType.INCONSISTENT,
                    "an exfiltration plan must send the target's content via send_message",
                    target,
                )


def _check_arguments(
    spec: ToolSpec,
    step: ToolCallStep,
    earlier: Mapping[str, ToolCallStep],
    entries: Mapping[tuple[str, str | None], ToolSpec],
    fixture_set: FixtureSetBundle,
    bad: Callable[..., None],
) -> str | None:
    """Validate a scripted call's arguments against the tool definition.

    Returns the asset ID the call addresses (for resource-bearing tools).
    """
    manifest = fixture_set.manifest.model
    for name in sorted(set(step.arguments) - set(spec.arguments)):
        bad(f"arguments.{name}", IssueType.UNDECLARED_ARGUMENT, "argument is not declared", name)
    for name, arg in spec.arguments.items():
        if arg.required and name not in step.arguments:
            bad(f"arguments.{name}", IssueType.MISSING_FIELD, "required argument missing", name)
    table_name = step.arguments.get("table")
    addressed: str | None = None
    for name, value in step.arguments.items():
        declared = spec.arguments.get(name)
        if declared is None:
            continue
        arg = declared
        where = f"arguments.{name}"
        if isinstance(value, ResultOf):
            source = earlier.get(value.result_of)
            source_spec = None if source is None else entries.get((source.tool, source.endpoint))
            if not isinstance(arg, StringArg):
                bad(where, IssueType.INVALID_TYPE, "only string arguments may carry a result", name)
            elif source_spec is None or not source_spec.returns_content:
                bad(
                    where,
                    IssueType.INCONSISTENT,
                    "referenced step returns no content",
                    value.result_of,
                )
            continue
        if isinstance(arg, StringArg):
            if not isinstance(value, str) or not arg.min_length <= len(value) <= arg.max_length:
                bad(
                    where,
                    IssueType.INVALID_VALUE,
                    f"must be a string of {arg.min_length}..{arg.max_length} characters",
                    name,
                )
        elif isinstance(arg, FixturePathArg):
            if not isinstance(value, str) or len(value) > arg.max_length:
                bad(where, IssueType.INVALID_VALUE, "must be a bounded fixture path", name)
            elif spec.resource.kind == "argument" and spec.resource.argument == name:
                asset = manifest.file_asset_by_path(value)
                if asset is None:
                    bad(where, IssueType.UNKNOWN_REFERENCE, "no fixture file at this path", value)
                else:
                    addressed = asset.asset_id
        elif isinstance(arg, FixtureTableArg):
            asset = manifest.asset(f"table:{value}") if isinstance(value, str) else None
            if asset is None:
                bad(where, IssueType.UNKNOWN_REFERENCE, "no such fixture table", str(value))
            else:
                addressed = asset.asset_id
        elif isinstance(arg, IntegerArg):
            if not isinstance(value, int) or not arg.minimum <= value <= arg.maximum:
                bad(
                    where,
                    IssueType.INVALID_VALUE,
                    f"must be an integer in {arg.minimum}..{arg.maximum}",
                    name,
                )
        elif isinstance(arg, FilterListArg):
            if not isinstance(value, tuple) or len(value) > arg.max_items:
                bad(where, IssueType.INVALID_VALUE, f"at most {arg.max_items} filters", name)
                continue
            table_asset = (
                manifest.asset(f"table:{table_name}") if isinstance(table_name, str) else None
            )
            columns = (
                set()
                if table_asset is None
                else {c.name for c in fixture_set.tables[table_asset.asset_id].model.columns}
            )
            for f_index, item in enumerate(value):
                if item.op not in arg.operators:
                    bad(
                        f"{where}[{f_index}].op",
                        IssueType.INVALID_ENUM,
                        "operator not allowed",
                        item.op,
                    )
                if item.column not in columns:
                    bad(
                        f"{where}[{f_index}].column",
                        IssueType.UNKNOWN_REFERENCE,
                        "no such column in the queried table",
                        item.column,
                    )
                if len(item.value) > arg.value_max_length:
                    bad(
                        f"{where}[{f_index}].value", IssueType.INVALID_VALUE, "value too long", name
                    )
    return addressed


def _check_agents(bundle: ConfigBundle, issues: _Issues) -> None:
    for (_agent_id, version), loaded in bundle.agents.items():
        agent = loaded.model
        src, ver = loaded.source, str(version)
        prompt_key = (agent.system_prompt.prompt_id, agent.system_prompt.version)
        if prompt_key not in bundle.prompts:
            issues.add(
                src,
                ver,
                "system_prompt",
                IssueType.UNKNOWN_REFERENCE,
                "no such prompt",
                f"{prompt_key[0]}_v{prompt_key[1]}",
            )
        if agent.tool_definitions_version not in bundle.tool_definitions:
            issues.add(
                src,
                ver,
                "tool_definitions_version",
                IssueType.UNKNOWN_REFERENCE,
                "no such tool definitions",
                agent.tool_definitions_version,
            )
        if not isinstance(agent, ScriptedAgentConfig):
            continue
        referenced_libraries: set[str] = set()
        for index, ref in enumerate(agent.scripted_plans):
            plan = bundle.scripted_plans.get((ref.template_id, ref.version))
            if plan is None:
                issues.add(
                    src,
                    ver,
                    f"scripted_plans[{index}]",
                    IssueType.UNKNOWN_REFERENCE,
                    "no such scripted plan",
                    f"{ref.template_id}@{ref.version}",
                )
                continue
            referenced_libraries.add(plan.model.template_library_version)
            if plan.model.tool_definitions_version != agent.tool_definitions_version:
                issues.add(
                    src,
                    ver,
                    f"scripted_plans[{index}]",
                    IssueType.INCONSISTENT,
                    "plan and agent must use the same tool definitions",
                    ref.template_id,
                )
            for target, steps in plan.model.variants.items():
                calls = sum(1 for s in steps if isinstance(s, ToolCallStep))
                if calls > agent.limits.max_steps:
                    issues.add(
                        src,
                        ver,
                        f"scripted_plans[{index}]",
                        IssueType.INCONSISTENT,
                        f"plan variant {target} makes {calls} calls > max_steps",
                        ref.template_id,
                    )
        covered = {r.template_id for r in agent.scripted_plans}
        for library_version in sorted(referenced_libraries):
            missing = sorted(set(bundle.template_libraries[library_version].templates) - covered)
            for template_id in missing:
                issues.add(
                    src,
                    ver,
                    "scripted_plans",
                    IssueType.MISSING_ARTIFACT,
                    f"no plan for {template_id} of {library_version}",
                    template_id,
                )


def _check_forbidden_content(bundle: ConfigBundle, issues: _Issues) -> None:
    """No URL anywhere; canaries and fabricated credentials only in their own asset."""
    credentials: dict[str, str] = {}
    marked_sources: set[str] = set()
    for fixture_set in bundle.fixture_sets.values():
        for asset in fixture_set.manifest.model.assets:
            for credential in asset.fabricated_credentials:
                credentials[credential] = asset.asset_id
            if asset.has_markers:
                marked_sources.add(
                    fixture_set.files[asset.asset_id].source
                    if asset.kind == "file"
                    else fixture_set.tables[asset.asset_id].source
                )

    documents: list[tuple[str, str | None, list[tuple[str, str]]]] = []
    for loaded in _all_yaml(bundle):
        documents.append(
            (
                loaded.source,
                loaded.model.identity()[1] if hasattr(type(loaded.model), "identity") else None,
                list(_strings(loaded.model.model_dump(mode="json"))),
            )
        )
    for raw in bundle.prompts.values():
        documents.append((raw.source, None, [("$", raw.text)]))
    for fixture_set in bundle.fixture_sets.values():
        for raw in fixture_set.files.values():
            documents.append((raw.source, fixture_set.version, [("$", raw.text)]))

    owner_by_source: dict[str, set[str]] = {}
    for fixture_set in bundle.fixture_sets.values():
        for asset in fixture_set.manifest.model.assets:
            source = (
                fixture_set.files[asset.asset_id].source
                if asset.kind == "file"
                else fixture_set.tables[asset.asset_id].source
            )
            owner_by_source[source] = set(asset.fabricated_credentials)

    for source, version, strings in documents:
        allowed_credentials = owner_by_source.get(source, set())
        for path, text in strings:
            url = _URL_RE.search(text)
            if url is not None:
                issues.add(
                    source,
                    version,
                    path,
                    IssueType.FORBIDDEN_CONTENT,
                    "URLs are not allowed in configuration",
                    url.group(0),
                )
            if (
                CANARY_PLACEHOLDER in text
                and source not in marked_sources
                and not source.endswith("manifest.yaml")
            ):
                issues.add(
                    source,
                    version,
                    path,
                    IssueType.FORBIDDEN_CONTENT,
                    "the canary placeholder belongs only in marked fixture assets",
                    CANARY_PLACEHOLDER,
                )
            for credential in credentials:
                if (
                    credential in text
                    and credential not in allowed_credentials
                    and not (source.endswith("manifest.yaml"))
                ):
                    issues.add(
                        source,
                        version,
                        path,
                        IssueType.FORBIDDEN_CONTENT,
                        f"fabricated credential of {credentials[credential]} appears "
                        "outside its asset",
                        credential,
                    )


def _all_yaml(bundle: ConfigBundle) -> Iterator[LoadedArtifact[Any]]:
    yield from bundle.attack_mappings.values()
    yield from bundle.phase_rules.values()
    yield from bundle.ttp_rules.values()
    yield from bundle.abstraction_tables.values()
    for library in bundle.template_libraries.values():
        yield from library.templates.values()
    yield from bundle.tasks.values()
    yield from bundle.tool_definitions.values()
    for fixture_set in bundle.fixture_sets.values():
        yield fixture_set.manifest
        yield from fixture_set.tables.values()
    yield from bundle.agents.values()
    yield from bundle.scripted_plans.values()
    yield from bundle.policies.values()
    yield from bundle.eval_configs.values()
