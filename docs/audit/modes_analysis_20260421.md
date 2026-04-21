# Modes-of-Reasoning Architecture Audit — FrankenEngine

Date: 2026-04-21  
Scope: `franken-engine` architecture pass using three compressed reasoning lenses: formal, adversarial, and operational.  
Skill: `modes-of-reasoning-project-analysis` applied in quick-synthesis mode because the user requested a 25-minute ship window.

## Context Pack

- Project identity: Rust-native JavaScript/TypeScript runtime substrate for deterministic execution, explicit authority boundaries, replay, evidence, and extension containment.
- Core substrate: Rust workspace under `crates/`, with `frankenengine-engine` as the core runtime and `frankenengine-extension-host` as the extension-host/policy surface.
- Deployment stage observed from docs: active development/pre-release. README states current verification happens through workspace crates and release utility binaries, not a shipped `frankenctl` installer.
- Project values from README and AGENTS: native Rust ownership, `#![forbid(unsafe_code)]`, deterministic-first behavior, evidence-before-claims, sibling substrate reuse, and no binding-led core execution path.
- Known limitation pre-filter: the certified rewrite optimizer is already tracked by `bd-1lsy.7.7.3.2`, so this audit does not create a duplicate bead for that disabled integration surface.

## Mode Selection

| Lens | Mode Equivalent | Why It Was Selected |
|---|---|---|
| Formal | Deductive / invariant checking | The architecture makes strong claims about deterministic replay, evidence, certification, and parser-to-runtime semantics. |
| Adversarial | Attack-surface review | The runtime explicitly targets adversarial extension workloads and revocation/capability enforcement. |
| Operational | Failure-mode / runbook analysis | The repository has many gates, docs, artifacts, and rapidly moving architecture surfaces that must remain verifiable by operators. |

## Finding 1 — Eval Lane Routing Is Textual, Not Semantic

- Lens: formal + adversarial.
- Evidence: `README.md:83` says FrankenEngine owns parser-to-scheduler semantics in Rust; `README.md:89` says deterministic behavior comes before adaptive behavior. `crates/franken-engine/src/lib.rs:1138` routes hybrid eval through `route_reason_for_source`, while `crates/franken-engine/src/lib.rs:1165` classifies module/throughput routing by substring checks for `import ` and `await `.
- Reasoning: route selection is part of observable execution evidence. A raw substring scan can be controlled by comments or string literals, causing a script-shaped input to be routed as module/throughput input before syntax-aware classification.
- Severity: medium for current pre-release state; higher once eval is exposed through a CLI/API.
- Confidence: 0.82. The route function is directly visible; exploitability depends on public exposure and exact parser behavior downstream.
- Bead: `bd-5w9um` — `[review][eval] Make hybrid eval route classification parser-aware`.

## Finding 2 — Revocation Audit Events Need Decision/Frontier Correlation

- Lens: adversarial + operational.
- Evidence: `crates/franken-engine/src/revocation_enforcement.rs:1` defines mandatory revocation enforcement points and states checks occur before mutation. `crates/franken-engine/src/revocation_enforcement.rs:132` defines `RevocationCheckEvent`, but the event only includes enforcement point, target id/type, revoked/transitive flags, trace id, and timestamp. README lines `46-48` emphasize deterministic replay, cryptographic governance, and revocation propagation.
- Reasoning: a revocation pass/fail event needs to be tied to the decision receipt and revocation frontier used for the decision. Without deterministic `decision_id`, `policy_id`, and chain frontier fields, later replay can show that a check occurred but not which policy decision and revocation head it was bound to.
- Severity: medium. The code has enforcement structure, but audit correlation is weaker than the governance claims require.
- Confidence: 0.78. The exact event schema is clear; downstream compensating evidence may exist elsewhere.
- Bead: `bd-2wxub` — `[review][revocation] Add decision/frontier correlation to revocation audit events`.

## Finding 3 — Architecture Counts Are Hand-Maintained Drift Surfaces

- Lens: operational.
- Evidence: `docs/ARCHITECTURE_OVERVIEW.md:7` describes a 455+ module codebase; `docs/ARCHITECTURE_OVERVIEW.md:117` says the gate system has 53 modules. `crates/franken-engine/src/lib.rs:5` begins the explicit public module list, and `crates/franken-engine/src/lib.rs:65` shows at least one intentionally disabled module surface. README lines `92-93` require evidence before claims.
- Reasoning: module and gate counts are architecture claims. In a fast-moving swarm, hand-maintained counts drift easily and become misleading onboarding/operator evidence unless generated from the workspace/module surface.
- Severity: low-to-medium. This is not a runtime vulnerability, but it weakens operational trust in architecture docs.
- Confidence: 0.86. The counts and rapidly changing module list are directly visible.
- Bead: `bd-1i2j0` — `[review][docs] Add generated architecture inventory to prevent module/gate count drift`.

## Confirmed Existing Risk — Certified Optimizer Disabled Surface

- Lens: formal.
- Evidence: `crates/franken-engine/src/lib.rs:65-71` comments out `certified_rewrite_optimizer`; the open bead `bd-1lsy.7.7.3.2` already tracks removal of the disabled integration-test suppression and the commented module export.
- Synthesis decision: not counted as a new finding bead to avoid duplicate scheduling. It remains the strongest formal-assurance gap because certified optimization claims are weaker while the module is not exported and integration tests are not active.

## Cross-Lens Synthesis

- Kernel: architecture claims should be bound to generated/checkable evidence. Formal and operational lenses both converged on the same pattern: deterministic/security claims are credible only when the route, audit, or inventory surface is machine-checkable.
- Supported: adversarial inputs matter at classification boundaries. The raw eval route scan is small code, but it sits at a high-leverage semantic boundary.
- Supported: audit records need replay-grade correlation, not just human-readable traces.
- Disputed/tempered: the architecture is intentionally ambitious. The operational lens should not penalize breadth itself; the issue is drift control for claims, not project scope.

## Verification Performed

- Static review: README architecture claims, `docs/ARCHITECTURE_OVERVIEW.md`, `crates/franken-engine/src/lib.rs`, `translation_validation.rs`, and `revocation_enforcement.rs`.
- Bead duplicate check: open beads were searched for certified optimizer, route classification, revocation audit, and architecture inventory duplicates.
- Dynamic check planned for this docs-only commit: `cargo check --lib -p frankenengine-engine` through the rch cargo hook with an isolated target directory.

## Created Beads

1. `bd-5w9um` — `[review][eval] Make hybrid eval route classification parser-aware`.
2. `bd-2wxub` — `[review][revocation] Add decision/frontier correlation to revocation audit events`.
3. `bd-1i2j0` — `[review][docs] Add generated architecture inventory to prevent module/gate count drift`.
