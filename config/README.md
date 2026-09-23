# Configuration-as-data (P2)

Trusted, version-controlled inputs to every engine (PRD §34 "MVP configuration-as-data
deliverables"; ARCHITECTURE.md §37; engineering plan §15). These files are executable
security and intelligence input, not documentation. Attacker-derived data is never
configuration: nothing in the platform turns a string, a database row or telemetry into
an artifact. Configuration enters only as files under this directory.

## Pipeline

Every artifact is loaded by `aitl_common.config` and goes through these stages:

```
file (confined to this root; no symlinks, no "..", size-limited, strict UTF-8)
  -> strict YAML subset (no duplicate keys, anchors, aliases, merge keys, tags;
     JSON scalars only, so `yes`/dates/octal/`.inf` stay strings)
  -> canonical JSON (aitl_common.canonical_json, P0)
  -> strict schema (pydantic, extra fields forbidden, no coercion)
  -> semantic checks -> cross-reference checks across all artifacts
  -> immutable model + content hash
```

`load_config(Path("config"))` returns a `ConfigBundle` only when the whole tree is valid.
Otherwise it raises one `ConfigValidationError` that lists every issue. Each issue has
`artifact`, `version`, `path`, `error_type` and `identifier`. There is no partial load and
no default or auto-correction.

## Layout and versions

| Artifact | File | Version identity |
|---|---|---|
| ATT&CK mapping | `attack/attack_mapping_v1.yaml` | `attack-mapping-v1` |
| Behavior-phase rules | `intel/phase_rules_v1.yaml` | `phase-rules-v1` |
| TTP rules | `intel/ttp_rules_v1.yaml` | `ttp-rules-v1` |
| Abstraction table | `abstraction/abstraction_table_v1.yaml` | `abstraction-table-v1` |
| Scenario templates | `scenarios/template_library_v1/T-01..T-03.yaml` | `template-library-v1` + template ID |
| Task library | `tasks/TK-1_v1.yaml` | `TK-1` v1 |
| Tool definitions | `tools/tool_definitions_v1.yaml` | `tool-definitions-v1` |
| Fixture set | `fixtures/fixture_set_v1/` (manifest, files, db, api) | `fixture-set-v1` |
| Agent configurations | `agents/assistant_llm_v1.yaml`, `agents/assistant_scripted_v1.yaml` | `agent_id` v1 |
| System prompt | `agents/prompts/system_v1.md` | `system` v1 (byte hash) |
| Scripted-agent plans | `agents/scripted_plans/T-01..T-03.yaml` | template ID + `version` in file |
| Baseline policy | `policies/baseline-permissive_v1.yaml` | `baseline-permissive` v1 |
| Target policy | `policies/target_v1.yaml` | `target` v1 |
| EvalConfig | `eval/eval-v1.yaml` | `eval-v1` |

- **Version identity.** The version in a file name must equal the version inside the
  file. Label-versioned artifacts use `<kind>-vN`, which matches the database
  `version_label` domain and fits beside `eval-v1` from the spec. Policies, agents and
  tasks use integer versions (`int` DB columns).
- **Explicit references.** Every reference between artifacts names an explicit version;
  nothing resolves to "latest".
- **No stray files.** Any file outside this layout is an error.

## Immutability

An accepted version is never edited. A change is a new file with the next version
(`target_v2.yaml`); the old one stays.

- **In CI.** `tests/config/test_artifact_lock.py` pins every accepted version by content
  hash. When you add a version, add a line there in review.
- **In the database.** `aitl_common.config.registry` refuses a registered version whose
  hash differs (`hash_mismatch`), inside one transaction that writes nothing.
- **What the hashes cover.** YAML artifacts are hashed as
  `canonical_sha256(validated model)`, so comments, key order and formatting do not change
  the hash. Prompts and fixture documents are hashed byte for byte.

## Security invariants (enforced by tests in `tests/config/`)

- **Four tools, pinned in code.** The tools are exactly `file_search`, `file_read`,
  `database_query` and `mock_api`. `mock_api` has exactly two endpoints:
  `directory_lookup` (internal) and `send_message` (external). Argument names, trust and
  resource semantics are pinned in code too, so YAML cannot add a tool, endpoint or
  argument, or relabel the exfiltration sink as internal.
- **Structured arguments only.** Arguments are bounded strings, canonical fixture paths,
  an enumerated table, a bounded filter list, or bounded integers. There is no SQL, URL or
  shell type, and no URL may appear in any artifact.
- **Scenario templates can't carry attacker data.** Templates are keyed by abstraction
  rule plus the pattern enums (`objective`, `target_tier`, `movement`). They have no field
  that can hold or reference attacker data. Their only parameter is the target fixture
  asset, drawn from a closed list.
- **Policies are checked exhaustively.** Over the finite decision-context space: no ties,
  no dead rules, no unknown roles, no wildcard role. `baseline-permissive` must ALLOW
  everything and cover every context. Each template's expected outcome must match the
  target policy.
- **Fixtures are fabricated and marked.** Every private or sensitive asset has exactly one
  canary placeholder and at least one fingerprintable line. Fabricated credentials start
  with `aitlfx-` and never appear outside their own asset anywhere in the repository
  (FR-004c).
- **Configuration code can't execute anything.** It never evaluates, executes, imports
  dynamically or shells out. Only `registry.py` touches the database, and only the six
  configuration tables.

## Engineering decisions (not spec requirements; revisit via a new version)

These fill details the frozen specification leaves open (CLAUDE.md Decision-Making Rules).

1. **Version labels** are `<kind>-vN`, e.g. `attack-mapping-v1`, matching `eval-v1` from
   the spec.
2. **ATT&CK release** is pinned to `enterprise-attack` 15.1. The 14 techniques of §37.1
   are pinned in `schemas/attack.py`.
3. **LLM model**: `anthropic` / `claude-sonnet-5`, `max_tokens` 2048. Plan assumption A1
   fixed the provider; §37.5 requires "one pinned model" but names none. The provider key
   and base URL are Gateway deployment configuration (P11), never agent data.
4. **Argument bounds** the spec does not fix:
   - `file_read.path` and `file_search.path_prefix` ≤ 256;
   - `directory_lookup.name` ≤ 128;
   - `send_message` recipient ≤ 128 and body ≤ 4000 (§16);
   - `database_query.limit` 1–100 and ≤ 5 filters (§16).
5. **Phase and TTP rule match kinds**:
   - `event_type`, `command`, `command_prefix` and `command_with_argument_prefix`;
   - TTP rules add `phase`, and every matching rule contributes;
   - TTP labels outside the curated subset (for example `resource_hijacking`) must be
     declared in `unmapped_labels` (FR-010).
6. **Template T-01** has two variants, keyed by its only parameter `target_asset`: the
   sensitive file (permission DENY) and the `api_keys` table (APPROVAL, auto-denied),
   following §37.3.
7. **Asset IDs** are `file:<path>`, `table:<name>` or `api:<name>`, following plan
   assumption A3.
8. **Table fingerprints**: for tables, each row (`" | "`-joined, declared column order) is
   the fingerprint "line".
9. **EvalConfig contents** are exactly weights plus thresholds (FR-029a). Policies and N
   belong to the replay request (§25); predicates belong to the templates (FR-034a).
