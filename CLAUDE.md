# Project

Adversary-in-the-Loop — Real-World AI Agent Security Proving Ground. This file governs how Claude Code works in this repository. It is a rules file, not a product description — read `PROJECT_VISION.md`, `PRD.md`, and `ARCHITECTURE.md` for what to build; read this file for how to build it.

# Mission

Implement, in order of priority, a system that: (1) captures attacker behavior from an isolated honeypot, (2) extracts and ATT&CK-maps TTPs, (3) abstracts them into agent-compatible threat patterns, (4) generates safe adversarial scenarios from those patterns, (5) executes them against a sandboxed agent behind a deterministic Tool Gateway + Policy Engine, (6) records the full trajectory, (7) computes blast radius, and (8) replays scenarios to produce quantitative before/after evidence. Every change should move the repository closer to demonstrating this full loop end-to-end, not toward a broader but shallower platform.

# Source of Truth

`PROJECT_VISION.md` is authoritative for intent and identity. `PRD.md` is authoritative for requirements (`FR-XXX`, `NFR-XXX`, `SEC-XXX` IDs) and MVP scope. `ARCHITECTURE.md` is authoritative for how requirements are implemented. This file is authoritative for engineering process. If any implementation decision would contradict `PROJECT_VISION.md`'s core loop (CAPTURE → UNDERSTAND → ABSTRACT → GENERATE → ATTACK → OBSERVE → CONTAIN → MEASURE → REPLAY → PROVE), stop and flag it rather than silently diverging.

# Core Architecture Principles

1. The AI agent never directly invokes a real tool. Every tool call passes through the Tool Gateway.
2. The Policy Engine's decision is deterministic and independent of the LLM's self-assessment.
3. The honeypot, the agent sandbox, and any trusted/production component are network-isolated from one another. The honeypot container has no network egress at all; telemetry leaves only through a one-way log volume read by the portless Log Shipper, which writes to INSERT-only staging tables (`PRD.md` FR-004a, FR-004b; `ARCHITECTURE.md §9`, ADR-009). Nothing in the platform ever opens a connection to the honeypot. An internet-exposed honeypot runs only on a separate host (`PRD.md` FR-004d, ADR-010).
4. Attacker-derived data is untrusted at every layer. It is sanitized at ingestion, and only its abstracted intent — an `AbstractedThreatPattern` made of controlled-vocabulary enums and foreign keys — reaches scenario generation; attacker text itself never does (never executed, never interpolated into config or scenario content). No scenario is ever generated directly from a TTP or raw behavior — the abstraction stage (`PRD.md §18a`) is mandatory for honeypot-derived and synthetic scenarios alike (`PRD.md` FR-010c).
5. Every security-relevant decision is logged immutably, and every `Scenario` carries an unbroken provenance chain back to the attack session it originated from (`PRD.md §29a`); a chain that originates in a fixture session is labeled `synthetic` but passes through exactly the same stages (`PRD.md` FR-045d).
6. Replay reproduces *configuration*, not LLM token output. Never describe or implement replay as "exact" or "identical" attack execution — it is a **controlled, scenario-equivalent replay**: the same locked execution configuration (scenario version, agent config, fixture set, sandbox seed, image digest, Gateway build, `EvalConfig`), re-executed, with as-run drift checked afterwards (`PRD.md` FR-031, FR-033, FR-033a).
7. The Gateway derives every input to a security decision — agent role, enforced and target policy, resource tier, taint state — from its own records via the execution's capability token; nothing the agent sends can select or influence its own evaluation context (`PRD.md` FR-019a).

# Security Principles

1. Never bypass the Tool Gateway, for any tool, for any reason, including "just for a quick test."
2. Never allow the LLM to directly access protected infrastructure, files, databases, or network resources.
3. Security controls fail closed: any Gateway/Policy Engine error, timeout, audit-write failure, or ambiguous state results in DENY for every tool operation, never ALLOW. There is no class of operation that fails open.
4. Honeypot infrastructure remains isolated from the agent sandbox and from any trusted/production infrastructure — no shared network namespace, no shared credentials, no shared filesystem. The single documented exception is the one-way `honeypot-logs` volume, writable by Cowrie and mounted read-only by the Log Shipper only (`ARCHITECTURE.md §9`, ADR-009).
5. Never use real secrets or production credentials anywhere in the honeypot or the agent sandbox. Use fixture/mock credentials only. The LLM provider key lives only in the Gateway's Model Proxy; the only credential inside a sandbox is its ephemeral single-execution capability token (`PRD.md` SEC-003).
6. Never expose the honeypot to unintended internal resources; the honeypot container's egress is none (default-deny, enforced at the network layer, `PRD.md` FR-004a).
7. Every security decision (ALLOW/DENY/APPROVAL, and the reason) must be auditable after the fact.
8. Core security decisions (permission policy, data-flow policy) are deterministic wherever practical — prefer rule tables over model calls for enforcement.
9. Do not use an LLM as the sole enforcement or classification mechanism for a critical security boundary (Tool Gateway decisions, TTP classification for the MVP). An LLM may *suggest*; it may not be the final authority.
10. Every major component (Tool Gateway, Policy Engine, TTP extraction, scenario generator, blast-radius engine, replay engine) must have automated tests before it is considered done.
11. Do not create stub/fake implementations and present them as complete. If something is intentionally stubbed for MVP scope (see `PRD.md §34`), label it clearly in code and docs as a stub with its deferred-to phase noted.
12. Do not silently remove or weaken a requirement from `PRD.md`. If a requirement turns out to be infeasible as written, flag it and propose a documented change rather than quietly dropping it.
13. Do not introduce unnecessary dependencies (no Kafka, no Kubernetes, no extra microservice) unless the requirement genuinely cannot be met with the current stack — justify in an ADR (`ARCHITECTURE.md §36`).
14. Do not over-engineer the MVP. Depth over breadth: the full loop working for one agent, one small tool set, and a curated ATT&CK subset beats a broad but shallow system.
15. Do not modify architecture without documenting the reason (update `ARCHITECTURE.md` and note the change, or add an ADR).
16. Do not claim a feature is complete without satisfying its `PRD.md` acceptance criteria.
17. Preserve reproducibility of replay experiments: scenario version, agent config, tool config, and policy version must always be recorded together (see `PRD.md` FR-031, FR-012, FR-022).
18. Maintain separation between untrusted attacker-derived data and trusted system configuration in both data model and code paths — never let attacker-derived strings reach a config file, environment variable, or executable path.
19. Treat all honeypot data as untrusted input, full stop, even after it has been through the pipeline once.
20. Sanitize attacker-derived content at ingestion (`PRD.md` FR-013); reject or quarantine what fails validation (FR-048) rather than forcing it through. Attacker text never reaches scenario generation at all (FR-010c, FR-011).
21. Keep the agent sandbox isolated and disposable — fresh per execution, torn down after, no cross-execution state leakage (`PRD.md` FR-016).
22. Never allow an attacker-controlled payload to directly become executable infrastructure configuration (no attacker string ever becomes a shell command, SQL fragment, config value, or scenario content; only the enum-valued output of the Adversary Abstraction Layer crosses into scenario generation).
23. All externally supplied data — honeypot content, documents the agent reads, tool responses, retrieved context — is untrusted and must be handled accordingly by agent-facing code.
24. Every table listed in `PRD.md` FR-044 — ingestion/intel records, versioned configuration (`Agent`, `AgentTask`, `Tool`, `DataAsset`), all security telemetry (`Policy`, `ToolInvocation`, `PolicyDecision`, `ToolResult`, `DataFlowEvent`, `SecurityViolation`, `SystemFailureEvent`, `ModelCall`, `AgentFinalResponse`, `Trajectory`), and all evaluation records — is append-only: no runtime role has UPDATE/DELETE, and there is no update/delete code path. Only `Scenario.status` (forward-only) and `Execution` lifecycle columns are mutable.

# Coding Principles

- Prefer simple, testable, explicit designs over clever or generic ones.
- Prefer small, composable services/modules with clear boundaries over one large monolith module, but do not create a new microservice just because a boundary exists conceptually — see Dependency Rules.
- Prefer configuration-as-data (YAML/JSON policy files, ATT&CK mapping tables) over configuration-as-code for anything a non-engineer reviewer needs to audit.
- Type-annotate Python code; validate all cross-boundary payloads (Gateway requests, scenario schema, API bodies) with explicit schemas (e.g., Pydantic).

# Repository Rules

- Inspect existing code before creating new abstractions; do not duplicate an existing module's responsibility.
- Read `PROJECT_VISION.md`, `PRD.md`, and `ARCHITECTURE.md` before modifying architecture or adding a new top-level component.
- Keep the honeypot, agent sandbox, Tool Gateway/Policy Engine, and dashboard as clearly separated top-level directories/services matching `ARCHITECTURE.md §5–6`.
- **Module-vs-service decision rule.** Default to adding a new module inside one of the five existing services (`ARCHITECTURE.md §6`). Only create a new deployable service when at least one of these is true: (a) the component needs independent horizontal scaling from everything else in its natural service; (b) the component sits on a different side of a trust/network boundary defined in `ARCHITECTURE.md §27–28` than everything else in its natural service; (c) the component has a genuinely different deployment cadence or failure-isolation requirement (e.g., it must be restartable without affecting the Tool Gateway's availability). "It felt like its own thing" is not sufficient justification. Any new service requires an ADR (`ARCHITECTURE.md §36`) stating which of (a)/(b)/(c) applies.

# Dependency Rules

- Do not add a new runtime dependency (library, service, infra component) without checking whether an existing dependency already satisfies the need.
- Do not introduce Kafka, Kubernetes, or additional databases "because it looks more serious" — the recommended stack (`ARCHITECTURE.md §24`, `PRD.md` Open Decisions) is the default; deviating requires an ADR (`ARCHITECTURE.md §36`).
- Pin dependency versions; do not use floating/latest tags for anything security-relevant (honeypot image, sandbox base image).

# Testing Rules

- Every `FR-XXX`/`SEC-XXX` with a stated acceptance criterion gets at least one automated test asserting that criterion.
- Tool Gateway and Policy Engine get dedicated unit tests covering ALLOW, DENY, APPROVAL, and fail-closed-on-error paths.
- Never hide, skip, or silently xfail a failing test to make CI green.
- Never weaken an assertion (e.g., loosening a fail-closed check) simply to make a test pass — fix the implementation instead, or flag the requirement as needing revision (Security Principle #12).
- Replay tests must assert that a scenario's baseline vs. protected outcomes differ in the expected direction on the fixture corpus. CI replay tests use the deterministic scripted test agent (`PRD.md` FR-001, FR-033a); live-LLM runs are evaluations, never CI tests, and are never used to make a test pass.
- Every MUST requirement maps to an entry in the test inventory (`ARCHITECTURE.md §33`); a requirement whose acceptance criterion says "code review" alone is not done.

# Documentation Rules

- If an implementation detail diverges from `ARCHITECTURE.md`, update `ARCHITECTURE.md` (or add an ADR) in the same change, with the reason for the divergence.
- If a requirement in `PRD.md` is reinterpreted or descoped, update `PRD.md` explicitly rather than leaving it stale.
- Keep this file (`CLAUDE.md`) and the other three documents mutually consistent; if a rule here would contradict `ARCHITECTURE.md`, resolve the conflict and update whichever document was wrong before proceeding with implementation.

# Agent Development Rules

- The agent implementation may only call tools through the defined Tool Gateway client interface; no direct library/network calls to a real tool from agent code.
- The agent's tool schema exposed to the LLM must exactly match the MVP-approved tool set (`PRD.md` FR-002); do not silently add tools "to make the demo richer."
- Agent prompts/instructions are trusted system configuration; content the agent reads (documents, tool results) is untrusted and must be clearly delimited from system instructions in the agent's context construction.
- The agent is a minimal purpose-built loop; do not adopt a third-party agent framework that ships built-in tools. Agent code's only network clients are the Gateway tool client and the Model Proxy client; it contains no LLM provider SDK or key (`PRD.md` FR-001, FR-019c).
- `mock_api` endpoints are a closed enumeration in tool configuration; adding one is a tool-set change under `PRD.md` FR-002, not a demo tweak.

# Sandbox Rules

- Each scenario execution gets a fresh, disposable sandbox instance; no shared mutable state across executions (`PRD.md` FR-016).
- Sandbox containers must have CPU/memory/time limits and be force-terminated on timeout (`PRD.md` FR-017).
- Fixture data (public/private/sensitive files, mock DB, mock APIs) lives in version-controlled fixtures, never real data. It is instantiated per execution behind the Gateway, never copied into the sandbox container (`ARCHITECTURE.md §14`, ADR-011).
- Sandbox containers are created only from the fixed, code-defined hardening template (non-root, all capabilities dropped, `no-new-privileges`, read-only root, no host mounts, no runtime socket, `sandbox-net` only) through the restricted container API proxy (ADR-019); request data never parameterizes that template.
- Executions are serialized in the MVP; enabling concurrency requires an ADR (`ARCHITECTURE.md §34`).

# Tool Gateway Rules

- The Gateway is the only code path with credentials/network access to real tool implementations (mock tools in MVP).
- Every request through the Gateway is logged before dispatch and every response is logged after receipt, regardless of decision.
- Gateway failure (exception, timeout, Policy Engine unreachable, audit-write failure) must resolve to DENY for every operation, record a `SystemFailureEvent`, and mark the execution `errored` — verify this with explicit failure-injection tests.
- The request is recorded on receipt, before policy evaluation; if any audit write fails, the Gateway denies and aborts (log-or-deny).
- Derive agent role, policy versions, run role, and resource tiers from the capability token and Gateway records; reject any client-supplied identity or context field (`PRD.md` FR-019, FR-019a).
- Canonicalize arguments before policy evaluation and dispatch the canonical form; no raw SQL, URLs, free-form paths, or content snippets from search (`PRD.md` FR-019b).

# Policy Engine Rules

- Policy is defined as structured, version-controlled configuration, not embedded conditional code scattered through the application.
- A decision is a pure function of `(policy version, decision context, taint snapshot)` where the context is `(agent_role, tool, endpoint, resource_tier, destination_trust)` (`PRD.md` NFR-002, FR-021, FR-025). Identical inputs must always yield the same decision — no I/O, no hidden randomness, no time-of-day logic, no reliance on LLM judgment inside the Policy Engine. Unmatched context is DENY.
- In a baseline run, the Gateway also records the target policy's (shadow) decision for every call; authorization metrics are always judged against the target policy (`PRD.md` FR-029).
- Data-flow policy evaluation is a distinct check from permission policy and can independently block a call that permission policy would allow (`PRD.md` FR-025).

# Honeypot Isolation Rules

- Zero egress from the honeypot container, enforced at the network layer (host firewall on the honeypot host; `internal` network in the single-host profile); Cowrie forwarding disabled, and download/fetch behavior restricted at the application layer and rendered non-functional by the zero-egress boundary (`PRD.md` FR-004a, ADR-023). Any exception must be explicitly justified in an ADR and reviewed.
- No shared secrets, credentials, or network namespace between the honeypot and any other component; the Log Shipper's `ingest_writer` role is INSERT-only on `intel_raw` and used by nothing else.
- Never publish a honeypot port from the single-host profile; internet exposure happens only in the `honeypot-host` profile on a separate host (`PRD.md` FR-004d).
- Honeypot and fixture data enter the rest of the system only through the Log Shipper (live or fixture mode) and `intel-service` promotion (`PRD.md` FR-005, FR-005b, FR-013), never through an ad hoc shortcut or a separate loader.

# Data Handling Rules

- Attacker-derived strings are stored in the `untrusted_text` column type and are never interpolated into shell commands, SQL, config files, or any scenario field.
- On output, attacker-derived text is escaped in the dashboard, JSON-encoded in logs, and formula-neutralized in CSV/JSON exports; attempted credentials are masked in the UI and excluded from exports (`PRD.md` SEC-009).
- Sensitive fixture data is tagged with a sensitivity tier at creation time (`PRD.md` FR-024) so data-flow policy can act on it.
- No real personal data or production data is ever used in fixtures, tests, or demos.

# Observability Rules

- Every major component exposes structured logs and a health check.
- Policy decisions, tool invocations, and security violations are logged with enough detail (actor, target, decision, reason, timestamp, policy/scenario version) to reconstruct the trajectory without re-running the scenario.

# Error Handling Rules

- Keep execution lifecycle (`pending`, `running`, `completed`, `errored`, `killed`) separate from security outcome flags (`had_enforced_deny`, `attack_attempted`, `attack_succeeded`, `task_succeeded`) (`PRD.md` FR-047). A policy block is an outcome, not a lifecycle state; `errored`/`killed` runs are excluded from metrics and never counted as blocks.
- Fail-closed denials caused by system errors are never counted as policy violations or unauthorized attempts (`PRD.md` FR-046).
- Malformed or invalid honeypot/scenario data is quarantined and flagged, not silently dropped or force-processed (`PRD.md` FR-048).
- Any fail-closed behavior triggered by an internal error is itself logged as a distinguishable event, not silently absorbed.

# Git Rules

- Commit messages reference the `FR-XXX`/`SEC-XXX`/`NFR-XXX` ID(s) a change addresses where applicable.
- Do not commit secrets, real credentials, or honeypot-exposed keys, ever, including in fixtures.
- Architecture-affecting commits include a one-paragraph rationale in the commit message or a linked ADR.

# Change Management Rules

- Significant architectural decisions are explained in the commit/PR description and reflected in `ARCHITECTURE.md §36` (ADRs).
- Scope changes to the MVP (`PRD.md §34`) require an explicit update to that section, not a silent expansion or contraction.

# Definition of Done

A change is done when: its stated acceptance criteria pass under automated test; relevant logging/audit trail exists; documentation is updated if architecture diverged; no security control was weakened to pass tests; and it does not silently expand MVP scope beyond `PRD.md §34` without an explicit, documented scope decision.

# Forbidden Shortcuts

- Do not let the agent call a real tool directly "just to get the demo working faster."
- Do not hardcode a Policy Engine decision inline in agent or Gateway code instead of consulting the configured policy.
- Do not fabricate or hardcode evaluation metrics instead of computing them from recorded trajectories (`PRD.md` FR-036).
- Do not replay a "similar" scenario and present it as the same scenario; a controlled, scenario-equivalent replay must reference the exact `Scenario` version ID and reuse the exact agent/tool/policy/seed configuration (`PRD.md` FR-031) — and must never be described as reproducing identical LLM output.
- Do not build a baseline/protected comparison where anything other than the Policy Engine configuration differs between the two runs (`PRD.md` FR-033a); if a "baseline" run drifted from the protected run's locked configuration or as-run values (including the provider-reported served model), the pair is `invalid_drift` and must not be reported as a valid comparison.
- Do not silently drop the data-flow check because the permission check already returned ALLOW.
- Do not score a baseline run's authorization against the baseline policy; "unauthorized" always means "not ALLOW under the target policy" (`PRD.md` FR-029).
- Do not version blast-radius weights or thresholds with policy; they belong to `EvalConfig` and are locked per pair (`PRD.md` FR-029a).
- Do not add a `source_reference` or any attacker-derived text to `Scenario`, and do not give the Scenario Generator read access to attacker-text tables (`PRD.md` FR-010c, FR-011).
- Do not make `Scenario.threat_pattern_id` nullable or write `AttackSession`/`AttackEvent` rows from anywhere but the promotion module, even for fixtures (`PRD.md` FR-005b, FR-045d).
- Do not let a sandbox request carry, and never trust, identity, role, policy, or data-tag fields (`PRD.md` FR-019a).
- Do not use an LLM to generate scenario content, judge task success, or judge attack success in the MVP (`PRD.md` FR-011, FR-034a).
- Do not let a `Scenario` reference a `TTP` or raw behavior record directly, skipping the `AbstractedThreatPattern` stage, even for a "quick test" scenario (`PRD.md` FR-010c).
- Do not present a fixture/synthetic scenario's results as real-attacker-derived; its provenance chain must be labeled `synthetic` (`PRD.md` FR-045d).
- Do not use production/real credentials "temporarily" in the sandbox or honeypot for convenience.

# Decision-Making Rules

- When the source material or the PRD does not resolve an engineering question, do not guess silently: propose a recommended option, note the trade-off, and mark it as an engineering decision (consistent with the `[OPEN DECISION]` items in `PRD.md §40`) rather than presenting it as an original requirement.
- When in doubt between a broader feature and the depth of the core loop, choose the core loop.
- When in doubt between an LLM-based and a deterministic mechanism for a security-relevant decision, choose deterministic.
