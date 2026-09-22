# Adversary-in-the-Loop

## 1. Executive Summary

Adversary-in-the-Loop is a real-world AI-agent security proving ground. It captures attacker behavior from an isolated SSH honeypot, extracts and classifies the underlying tactics, techniques, and procedures (TTPs), maps them to MITRE ATT&CK, transforms them into safe reproducible adversarial scenarios, and executes those scenarios against a sandboxed autonomous AI agent. A deterministic runtime security boundary (Tool Gateway + Policy Engine) sits between the agent's decisions and any real action or data flow. The system records the agent's full tool-call trajectory, calculates a formal blast-radius score for any unauthorized behavior, and runs the same scenario — under a controlled, scenario-equivalent replay with an identical configuration — before and after a defense is enabled, to produce quantitative, reproducible evidence of whether that defense works.

The system is not a honeypot, not a prompt-injection filter, not a SIEM, and not a red-team dashboard. It is an experimental evaluation platform whose central artifact is *evidence*: a before/after comparison showing that a specific runtime control measurably reduced unauthorized agent behavior and blast radius while preserving the agent's ability to complete its legitimate task.

## 2. Problem Statement

Autonomous AI agents increasingly take real actions: reading and writing files, querying databases, calling APIs, sending email, and invoking external tools. Because agents consume untrusted content (documents, web pages, emails, tool responses, retrieved context, memory), they are exposed to adversarial instructions embedded in that content — prompt injection, tool poisoning, and related attack classes. Existing evaluation methodology for this class of risk is dominated by synthetic, hand-authored test cases: engineers imagine an attack, encode it as a fixed scenario, and check whether the agent resists it. This tells us whether an agent survives one specific scenario invented by its own defenders. It says very little about whether an agent would survive attacker behavior that actually occurs against real, exposed systems, which is adaptive, exploratory, and not bound by any test author's imagination.

## 3. Why This Problem Matters

As agents are given more autonomy and more powerful tools, the cost of a successful compromise rises from "bad chatbot answer" to "unauthorized database access," "silent data exfiltration," or "irreversible external action." Security evaluation that relies solely on synthetic scenarios systematically under-samples the space of real adversarial behavior, and it provides no standing mechanism to prove that a fix, once shipped, continues to hold. Both gaps — realism of the attack corpus, and durability of the proof — are addressable with engineering, and both are largely absent from current agent-security tooling.

## 4. Current Gap

Three deficiencies recur across existing approaches:

- **Attack realism gap.** Synthetic test suites are static and reflect what defenders anticipated, not what attackers actually do.
- **Enforcement gap.** Many "AI security" tools rely on another model to detect bad behavior after the fact, rather than placing a deterministic boundary between agent decisions and real-world actions.
- **Proof gap.** Even when a mitigation is added, most tooling does not re-run the *exact same* attack under before/after conditions and report the *quantified* change in outcome (blast radius, unauthorized actions, task preservation).

## 5. Proposed Solution

Adversary-in-the-Loop closes all three gaps at once by building a closed loop: real attacker behavior is captured by an isolated SSH honeypot and never allowed to touch the agent sandbox directly; it is abstracted into safe, reproducible scenarios that preserve attacker *intent* (what they were trying to accomplish) rather than raw literal commands; those scenarios are executed against a sandboxed agent behind a deterministic Tool Gateway and Policy Engine; the resulting trajectory is scored for blast radius and policy violations; and the same scenario, under an identical configuration, is run again as a controlled, scenario-equivalent replay under baseline and protected conditions to produce a reproducible before/after comparison.

## 6. Core Innovation

The project's innovation is the combination, not any single piece in isolation:

1. **Real-world adversary intelligence** as the source material for agent-security scenarios, rather than exclusively synthetic ones.
2. **Agent-specific adversarial replay** — observed behavior is abstracted into intent-preserving scenarios designed for tool-using agents, not raw command replay.
3. **Runtime action security** — a deterministic boundary between AI decision and real-world action, so the LLM is never the sole enforcement mechanism.
4. **Quantitative proof** — blast radius, unauthorized-action counts, and task-completion rate are measured before and after a mitigation, on the same scenario under a controlled, scenario-equivalent replay, so the claim "the defense works" is evidence-backed rather than asserted.

## 7. Core System Loop

```
CAPTURE → UNDERSTAND → ABSTRACT → GENERATE → ATTACK → OBSERVE → CONTAIN → MEASURE → REPLAY → PROVE
```

- **Capture** — real attacker sessions from the isolated honeypot.
- **Understand** — reconstruct behavior and extract TTPs, mapped to MITRE ATT&CK.
- **Abstract** — translate a network-layer TTP into an agent-compatible threat pattern: not "what shell commands did the attacker type" but "what was the attacker trying to accomplish, expressed in terms an autonomous agent's action space (tool calls, data access, data movement) can represent." This is the intellectual center of the project and is detailed in §8 and in `ARCHITECTURE.md §13`.
- **Generate** — instantiate the abstracted threat pattern as a concrete, schema-validated, safe adversarial scenario.
- **Attack** — execute a scenario against the sandboxed agent alongside its legitimate task.
- **Observe** — record the complete tool-call trajectory.
- **Contain** — enforce deterministic permission and data-flow policy at the Tool Gateway.
- **Measure** — compute blast radius, violation counts, and task-completion outcome.
- **Replay** — re-run the same scenario, under the same configuration, under baseline vs. protected conditions (a *controlled, scenario-equivalent* replay — see §8 and `PRD.md §26`, since an LLM-driven agent's exact output is not itself claimed to be deterministic).
- **Prove** — report the quantified before/after difference, with a full provenance trail back to the originating honeypot session (§9, §12).

## 8. How the System Works

An isolated Cowrie-based SSH honeypot exposes a fake environment to the open internet and records session activity with no path back into any other part of the system. A collection pipeline converts raw session logs into a structured behavioral timeline (login → discovery → probing → attempted access), which a TTP extraction stage classifies and maps to MITRE ATT&CK techniques with a confidence score. A scenario generator takes a selected TTP and produces an abstract, parameterized adversarial scenario describing an objective, an entry point (e.g., a poisoned document the agent reads), a target resource, the tools available, and the policy expected to stop it — never the attacker's literal shell commands.

Between TTP/ATT&CK mapping and scenario generation sits the **Adversary Abstraction Layer**. This is the answer to the question a skeptical reviewer will always ask first: *"How is an SSH attack actually relevant to an AI agent?"* The system does not replay SSH commands against an agent — an agent has no shell to type into. Instead, each ATT&CK-mapped TTP is translated into an **agent-compatible threat pattern**: a technique-agnostic statement of adversarial intent (e.g., "attempt to discover and access a resource outside the actor's authorized scope," or "attempt to move sensitive content to an unauthorized destination") together with the ATT&CK tactic it corresponds to. That threat pattern, not the raw attacker payload, is what the scenario generator instantiates into a concrete scenario expressed entirely in the agent's own action space (tool calls, data reads, data movement). This is what makes the honeypot corpus meaningfully connected to agent security rather than a superficial theming device. Full mechanics in `ARCHITECTURE.md §13`; requirements in `PRD.md §19` (Adversary Abstraction Requirements).

The scenario is loaded into a disposable agent sandbox containing a small set of controlled tools (file search/read, database query, mock APIs, email). The agent is simultaneously given a legitimate task and exposed to the adversarial content. Every tool call it attempts passes through a Tool Gateway, which consults a Policy Engine (permission policy plus a lightweight data-flow policy) and returns ALLOW, DENY, or REQUIRE-APPROVAL — a decision that is deterministic and independent of the LLM's own judgment. The full trajectory is logged, blast radius is computed from the resources actually reached, and the same scenario can be re-executed on demand — before a policy exists and after — to produce a reproducible before/after record.

## 9. Key Capabilities

- Isolated honeypot-based attacker telemetry collection, over a strictly one-way, write-only telemetry path (§8 below; `ARCHITECTURE.md §9`).
- Behavioral timeline reconstruction and MITRE ATT&CK-mapped TTP extraction.
- An explicit Adversary Abstraction Layer that converts a TTP into an agent-compatible threat pattern before any scenario is generated (§8; `ARCHITECTURE.md §13`).
- Safe, intent-preserving adversarial scenario generation from that abstracted pattern — never from raw attacker payload.
- Sandboxed, tool-using AI agent with a bounded, controlled tool surface.
- Deterministic Tool Gateway and Policy Engine (permission + data-flow) separating agent decisions from real actions.
- Full tool-call trajectory recording.
- A formal blast-radius score, computed from a documented, weighted formula, not just raw counts (`ARCHITECTURE.md §20`).
- An unbroken **attack provenance chain** — honeypot session → attack event → behavior → TTP/technique → abstracted threat pattern → scenario → agent run → policy decision → blast radius → replay result — queryable and displayable end to end (§9, §12).
- Controlled, scenario-equivalent attack replay (same scenario version, same configuration) with baseline vs. protected comparison.
- Evaluation dashboard presenting the attacker → TTP → abstraction → scenario → agent → policy → outcome → blast radius → replay story end to end, including the provenance chain for any result.

## 10. Differentiation

Adversary-in-the-Loop is deliberately narrower than a general AI-agent governance platform and deliberately more operational than a threat-intelligence dashboard. It is not a honeypot (the honeypot is only the intelligence source), not a prompt-injection classifier (agent behavior and tool interaction are evaluated, not just text), not an LLM firewall (it protects actions and data flow, not just filters text), not a SIEM (attacker behavior becomes a reproducible experiment, not a log archive), and not generic red teaming (it additionally asks whether containment holds and whether that can be proven on replay). See `PRD.md §6` and `ARCHITECTURE.md §2` for how this shapes concrete scope decisions.

Two concrete, demonstrable artifacts carry this differentiation beyond narrative: the **Adversary Abstraction Layer** (§8), which gives a precise, inspectable answer to "how is this SSH attack relevant to an AI agent," and the **attack provenance chain** (§9, §12), which lets any result on the dashboard be traced backward, link by link, to the exact honeypot session it originated from. Neither is decoration — both are load-bearing requirements (`PRD.md §19`, `PRD.md §29`) with acceptance criteria, not just dashboard flourishes.

## 11. Target Users

- **AI security engineers / red teams** evaluating whether an agent's runtime controls actually stop realistic adversarial behavior.
- **Agent framework and platform engineers** who need evidence, not opinion, that a proposed guardrail reduces risk without breaking legitimate tasks.
- **Security researchers** studying whether real-world-derived adversarial corpora expose gaps that synthetic test suites miss.
- **Students / hackathon and portfolio engineers** building a deep, defensible AI-security systems project.

## 12. Example End-to-End Scenario

The honeypot observes an attacker enumerate accessible files and attempt to read what looks like credential material, then attempt outbound data transfer. TTP extraction classifies this as Discovery followed by Collection followed by Exfiltration-Attempt behavior and maps it to the corresponding ATT&CK techniques. The Adversary Abstraction Layer translates this into an agent-compatible threat pattern: "attempt to locate content resembling access credentials outside the actor's authorized scope, then move it to an external destination." The scenario generator instantiates that pattern as a concrete scenario: a document the agent is asked to summarize contains an embedded instruction directing the agent to locate "credentials" in a sensitive file and email them externally. The agent, given the legitimate task "summarize this document," is exposed to the poisoned content. It attempts a `read_sensitive_file` call. The Tool Gateway checks policy: sensitive-file read is DENY for this agent's role. The call is blocked, logged, and the blast radius is recorded as zero unauthorized resources reached, while the legitimate summarization task still completes. The same scenario version is then run again — a controlled, scenario-equivalent replay under an identical configuration — with the policy disabled (baseline) to show the same attempt would have succeeded, producing the before/after contrast — and the resulting record can be traced backward through its full provenance chain to the originating honeypot session.

## 13. Killer Demo

Live, in five acts: (1) the agent completes a normal task; (2) an adversarial scenario derived from a real honeypot session is injected and the agent attempts an unauthorized action; (3) the Tool Gateway blocks it and the dashboard shows the denial in real time; (4) the dashboard displays blast radius = minimal and legitimate task preserved; (5) the operator presses **Replay Attack** and the scenario-equivalent replay — same scenario version, same configuration — is blocked again, demonstrating the defense is standing infrastructure, not a one-off manual fix. At any point the operator can click "Where did this come from?" and the dashboard walks the provenance chain back to the exact honeypot session, attack event, and behavior that produced the scenario — turning the abstract claim "this is derived from a real attack" into a concrete, inspectable fact.

## 14. Research Potential

The project supports a defensible empirical research question: *can real-world attacker behavior captured from an isolated honeypot be transformed into reproducible adversarial scenarios that meaningfully evaluate and improve the runtime security of autonomous AI agents?* Secondary questions (full detail in `PRD.md §27` / research framing) concern whether real-world-derived scenarios expose behaviors synthetic suites miss, whether runtime tool-boundary policy measurably reduces unauthorized actions, whether blast radius can be reduced without breaking task completion, and whether replay provides reproducible evidence across runs. The project explicitly avoids claiming the system proves an agent is "secure" — it claims only that specific, measured attacks were contained, and that the containment is reproducible.

## 15. Long-Term Vision

The mature system, described architecturally in `ARCHITECTURE.md §35`, extends the MVP loop into a security-learning loop: a successful unauthorized action's root cause is traced to a missing or misconfigured policy, a proposed policy is generated, the same scenario is run again as a controlled, scenario-equivalent replay against the proposed policy, and the policy is validated before promotion. Longer-term extensions could broaden the honeypot corpus, the ATT&CK technique coverage, the tool surface, and the agent/model matrix under test — always preserving the core loop rather than diluting it into a general-purpose platform.

## 16. Project Principles

- The security boundary must be deterministic; the LLM is never trusted solely because it produced an action.
- Real attacker data is treated as untrusted input at every stage until sanitized and abstracted.
- The honeypot, the agent sandbox, and production infrastructure remain strictly isolated from one another.
- Depth over breadth: a small system that proves the full loop beats a large system that proves nothing conclusively.
- Every claim of "the defense works" must be backed by a reproducible replay with quantified before/after metrics.
- Language stays defensible: the system *measures*, *contains*, *reduces*, and *verifies* — it does not claim to *guarantee* security.

## 17. Scope Boundaries

In scope for the project's identity: honeypot-derived intelligence, TTP/ATT&CK mapping, scenario generation, sandboxed agent execution, deterministic runtime containment, trajectory recording, blast-radius measurement, and replay-based evaluation. Out of scope for the project's identity (though individually useful technologies): becoming a full enterprise SIEM, a universal penetration-testing platform, a general-purpose autonomous SOC, exhaustive multi-LLM/multi-framework support, or coverage of the entire MITRE ATT&CK matrix. See `PRD.md §5` (Non-Goals) and `PRD.md §34–36` (MVP / Phase 2 / Future Scope) for the authoritative scope cut.
