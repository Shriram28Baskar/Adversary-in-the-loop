# Project

Adversary-in-the-Loop — Real-World AI Agent Security Proving Ground. This file governs how Claude Code works in this repository. It is a rules file, not a product description — read `PROJECT_VISION.md`, `PRD.md`, and `ARCHITECTURE.md` for what to build; read this file for how to build it.

# Mission

Implement, in order of priority, a system that: (1) captures attacker behavior from an isolated honeypot, (2) extracts and ATT&CK-maps TTPs, (3) generates safe adversarial scenarios, (4) executes them against a sandboxed agent behind a deterministic Tool Gateway + Policy Engine, (5) records the full trajectory, (6) computes blast radius, and (7) replays scenarios to produce quantitative before/after evidence. Every change should move the repository closer to demonstrating this full loop end-to-end, not toward a broader but shallower platform.

# Source of Truth

`PROJECT_VISION.md` is authoritative for intent and identity. `PRD.md` is authoritative for requirements (`FR-XXX`, `NFR-XXX`, `SEC-XXX` IDs) and MVP scope. `ARCHITECTURE.md` is authoritative for how requirements are implemented. This file is authoritative for engineering process. If any implementation decision would contradict `PROJECT_VISION.md`'s core loop (CAPTURE → UNDERSTAND → GENERATE → ATTACK → OBSERVE → CONTAIN → MEASURE → REPLAY → PROVE), stop and flag it rather than silently diverging.

# Core Architecture Principles

1. The AI agent never directly invokes a real tool. Every tool call passes through the Tool Gateway.
2. The Policy Engine's decision is deterministic and independent of the LLM's self-assessment.
3. The honeypot, the agent sandbox, and any trusted/production component are network-isolated from one another; the honeypot's only permitted network path outward is a one-way, write-only telemetry export (`PRD.md` FR-004b) — nothing in the platform ever opens a connection back to the honeypot.
4. Attacker-derived data is untrusted at every layer until it has passed sanitization and been transformed, via the Adversary Abstraction Layer, into an `AbstractedThreatPattern` and then a scenario (never executed, never interpolated into config). No scenario is ever generated directly from a TTP or raw behavior — the abstraction stage (`PRD.md §18a`) is mandatory and cannot be skipped (`PRD.md` FR-010c).
5. Every security-relevant decision is logged immutably, and every `Scenario` carries an unbroken provenance chain back to the honeypot session it originated from (`PRD.md §29a`) — or is explicitly labeled `synthetic` if it did not (`PRD.md` FR-045d).
6. Replay reproduces *configuration*, not LLM token output. Never describe or implement replay as "exact" or "identical" attack execution — it is a **controlled, scenario-equivalent replay**: same scenario version, same agent/tool/policy configuration, same sandbox seed, re-executed (`PRD.md` FR-031, FR-033).

# Security Principles

1. Never bypass the Tool Gateway, for any tool, for any reason, including "just for a quick test."
2. Never allow the LLM to directly access protected infrastructure, files, databases, or network resources.
3. Security controls fail closed: any Gateway/Policy Engine error, timeout, or ambiguous state results in DENY for protected operations, never ALLOW.
4. Honeypot infrastructure remains isolated from the agent sandbox and from any trusted/production infrastructure — no shared network namespace, no shared credentials, no shared filesystem.
5. Never use real secrets or production credentials anywhere in the honeypot or the agent sandbox. Use fixture/mock credentials only.
6. Never expose the honeypot to unintended internal resources; its only legitimate egress is none (default-deny egress).
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
20. Validate and sanitize attacker-derived content before it reaches scenario generation (`PRD.md` FR-013); reject or quarantine what fails validation (FR-048) rather than forcing it through.
21. Keep the agent sandbox isolated and disposable — fresh per execution, torn down after, no cross-execution state leakage (`PRD.md` FR-016).
22. Never allow an attacker-controlled payload to directly become executable infrastructure configuration (no attacker string ever becomes a shell command, SQL fragment, or config value without going through the sanitized-scenario abstraction layer).
23. All externally supplied data — honeypot content, documents the agent reads, tool responses, retrieved context — is untrusted and must be handled accordingly by agent-facing code.
24. Security telemetry (`PolicyDecision`, `ToolInvocation`, `SecurityViolation`) is immutable/append-only at the data-access layer; there is no update/delete code path for these tables in the MVP.

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
- Replay tests must assert that a scenario's baseline vs. protected outcomes differ in the expected direction on the fixture corpus.

# Documentation Rules

- If an implementation detail diverges from `ARCHITECTURE.md`, update `ARCHITECTURE.md` (or add an ADR) in the same change, with the reason for the divergence.
- If a requirement in `PRD.md` is reinterpreted or descoped, update `PRD.md` explicitly rather than leaving it stale.
- Keep this file (`CLAUDE.md`) and the other three documents mutually consistent; if a rule here would contradict `ARCHITECTURE.md`, resolve the conflict and update whichever document was wrong before proceeding with implementation.

# Agent Development Rules

- The agent implementation may only call tools through the defined Tool Gateway client interface; no direct library/network calls to a real tool from agent code.
- The agent's tool schema exposed to the LLM must exactly match the MVP-approved tool set (`PRD.md` FR-002); do not silently add tools "to make the demo richer."
- Agent prompts/instructions are trusted system configuration; content the agent reads (documents, tool results) is untrusted and must be clearly delimited from system instructions in the agent's context construction.

# Sandbox Rules

- Each scenario execution gets a fresh, disposable sandbox instance; no shared mutable state across executions (`PRD.md` FR-016).
- Sandbox containers must have CPU/memory/time limits and be force-terminated on timeout (`PRD.md` FR-017).
- Fixture data (public/private/sensitive files, mock DB, mock APIs) lives in version-controlled fixtures, never real data.

# Tool Gateway Rules

- The Gateway is the only code path with credentials/network access to real tool implementations (mock tools in MVP).
- Every request through the Gateway is logged before dispatch and every response is logged after receipt, regardless of decision.
- Gateway failure (exception, timeout, Policy Engine unreachable) must resolve to DENY for protected operations — verify this with an explicit failure-injection test.

# Policy Engine Rules

- Policy is defined as structured, version-controlled configuration, not embedded conditional code scattered through the application.
- A given (agent role, tool, policy version) tuple must always yield the same decision — no hidden randomness, no time-of-day logic, no reliance on LLM judgment inside the Policy Engine.
- Data-flow policy evaluation is a distinct check from permission policy and can independently block a call that permission policy would allow (`PRD.md` FR-025).

# Honeypot Isolation Rules

- Default-deny egress from the honeypot container; any exception must be explicitly justified and reviewed.
- No shared secrets, credentials, or network namespace between the honeypot and any other component.
- Honeypot data enters the rest of the system only through the defined collection/sanitization pipeline (`PRD.md` FR-005, FR-013), never through an ad hoc shortcut.

# Data Handling Rules

- Attacker-derived strings are stored as opaque/untrusted text and are never directly interpolated into shell commands, SQL, config files, or scenario-executable fields.
- Sensitive fixture data is tagged with a sensitivity tier at creation time (`PRD.md` FR-024) so data-flow policy can act on it.
- No real personal data or production data is ever used in fixtures, tests, or demos.

# Observability Rules

- Every major component exposes structured logs and a health check.
- Policy decisions, tool invocations, and security violations are logged with enough detail (actor, target, decision, reason, timestamp, policy/scenario version) to reconstruct the trajectory without re-running the scenario.

# Error Handling Rules

- Distinguish `errored` (system/infra failure) from `blocked` (policy denied) from `completed` (ran to completion) execution states; never conflate them in metrics.
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
- Do not build a baseline/protected comparison where anything other than the Policy Engine configuration differs between the two runs (`PRD.md` FR-033a); if a "baseline" run drifted from the protected run's scenario version, agent config, tool config, or seed, it is not a valid comparison and must not be reported as one.
- Do not silently drop the data-flow check because the permission check already returned ALLOW.
- Do not let a `Scenario` reference a `TTP` or raw behavior record directly, skipping the `AbstractedThreatPattern` stage, even for a "quick test" scenario (`PRD.md` FR-010c).
- Do not present a fixture/synthetic scenario's results as real-attacker-derived; its provenance chain must be labeled `synthetic` (`PRD.md` FR-045d).
- Do not use production/real credentials "temporarily" in the sandbox or honeypot for convenience.

# Decision-Making Rules

- When the source material or the PRD does not resolve an engineering question, do not guess silently: propose a recommended option, note the trade-off, and mark it as an engineering decision (consistent with the `[OPEN DECISION]` items in `PRD.md §40`) rather than presenting it as an original requirement.
- When in doubt between a broader feature and the depth of the core loop, choose the core loop.
- When in doubt between an LLM-based and a deterministic mechanism for a security-relevant decision, choose deterministic.
