# FrankenEngine Native Architecture Synthesis

This document defines the FrankenEngine-native architecture synthesized from semantic requirements in `docs/SEMANTIC_DONOR_SPEC.md`.

It is intentionally de novo: semantics are imported as behavioral requirements, while architecture remains owned by FrankenEngine design goals (security, deterministic replay, and evidence-first operations).

## 1. Executive Summary

FrankenEngine's architectural identity is a native Rust runtime with policy-aware execution semantics, deterministic replay, and auditable security decisions as first-class runtime artifacts. The synthesis objective is not to emulate donor internals from V8 or QuickJS, but to guarantee compatibility at the behavior surface while preserving architectural freedom for FrankenEngine's thesis. The thesis itself combines four constraints: security-first containment, deterministic forensic replay, performance under explicit proofs, and strict runtime ownership boundaries that reject binding-led core execution. This creates a different optimization target than generic JavaScript engines. Traditional engine design optimizes for broad throughput under mostly trusted code assumptions; FrankenEngine optimizes for adversarial extension workloads where authority minimization, evidence emission, and replayability are non-optional.

The synthesis model therefore separates inputs from outputs. Inputs are semantic contracts, edge-case catalogs, and compatibility-critical test vectors defined in the donor spec and plan sections 4.1 and 10.1. Outputs are native design choices for parser architecture, IR contracts, memory domains, execution slots, and proof-guided optimization lanes that satisfy those semantics without donor pipeline mirroring. Every synthesis choice in this document traces to one or more plan anchors and one or more thesis goals. Where donor engines solve similar semantic obligations, this document treats those implementations as non-binding existence proofs, not design templates. The result is a blueprint that the section 10.2 VM Core implementation can execute directly while remaining constitutionally compatible with AGENTS-level prohibitions on donor architecture transplantation and with the repo split contract that keeps compatibility UX outside the engine core.

## 2. Parser Strategy

FrankenEngine adopts an arena-allocated recursive-descent parser with explicit script/module goal selection and deterministic AST canonicalization. The rationale is traceable to Plan sections 10.2 (parser trait + canonical AST invariants), 4.1 (spec-first bootstrap), and 5.1/5.2 (optimization rigor + mathematical decision clarity). The parser must satisfy two independent obligations: semantic correctness against the donor-derived behavior contract and stable structural output for downstream IR hashing, replay equivalence checks, and policy proofs. A recursive-descent design with explicit state machines for context-sensitive grammar features provides transparent control over these obligations while preserving straightforward diagnostic boundaries for deterministic error taxonomy.

Arena allocation is selected because it makes parse-time object lifetimes predictable and minimizes allocator jitter in parser-critical hot paths. This supports deterministic replay and reproducible parsing artifacts by reducing incidental heap variation across runs. Canonical AST serialization is mandatory: node ordering, span normalization, and literal representation are fixed by contract so that semantically identical sources produce stable AST hashes. Those hashes become anchors for conformance artifacts, policy checkpoints, and replay manifests.

This strategy explicitly rejects donor parser architecture mirroring. We do not import hidden parser staging layers, donor-specific pre-parser shortcuts, or donor bytecode-oriented parse outputs. The parser is designed around FrankenEngine's IR pipeline requirements rather than donor backend assumptions. Parse diagnostics are also policy-aware: parser output includes deterministic code namespaces and structured metadata compatible with `trace_id`, `decision_id`, and `policy_id` propagation downstream. The operational consequence is a parser subsystem that is simultaneously semantic-compatible, replay-stable, and compositionally aligned with capability-typed IR contracts without inheriting donor architecture debt.

## 3. IR Pipeline Design

FrankenEngine's IR synthesis uses a five-level contract (`IR0` through `IR4`) because the runtime must encode semantics, authority constraints, information-flow obligations, optimization proofs, and execution artifacts as separate but linkable layers. This directly traces to Plan section 10.2 (multi-level IR + IFC labeling + proof linkage), section 9A.1 (capability-typed execution), section 9A.7 (policy lattice), and section 9I moonshot requirements for self-replacement and proof-bearing promotion. A thinner donor-style pipeline is insufficient for this objective because it collapses security and optimization concerns into internal compiler heuristics that are difficult to replay and audit.

`IR0` (`SyntaxIR`) captures syntactic-normalized program structure from canonical AST in a form optimized for deterministic lowering diagnostics. `IR1` (`SpecIR`) introduces explicit spec-level scope/binding resolution, control/data-flow primitives, and deterministic effect ordering. `IR2` (`CapabilityIR`) is the policy-bearing layer: capability labels, IFC source/sink metadata, declassification obligations, and hostcall intent typing are attached here so flow legality and authority envelopes are statically visible. `IR3` (`ExecIR`) is the execution-ready flat register-VM instruction stream carrying proof-to-specialization linkage, explicit preconditions, validity epochs, and rollback tokens. `IR4` (`WitnessIR`) is the post-execution witness and forensic trace layer emitted by runtime execution for deterministic replay, audit verification, and equivalence checking.

Each transition is a verified pass with witness emission. Witnesses include stable IDs, input/output hash links, and failure semantics when invariants do not hold. This pass-by-pass witness chain enables deterministic replay of compiler decisions and supports downstream incident forensics where execution behavior must be explained in terms of approved transformations rather than opaque optimization internals. The pipeline also supports safe-mode fallback: if proof obligations fail or model uncertainty exceeds configured bounds, execution reverts deterministically to unspecialized legal IR forms.

This synthesis explicitly avoids donor architecture patterns such as donor bytecode dependence, speculative optimization gates without proof linkage, and hidden feedback-vector coupling as a semantic requirement. The IR design is not trying to recreate donor throughput tactics; it is creating a provable execution substrate where security constraints and performance transforms are jointly represented and machine-auditable.

## 4. Memory Model

FrankenEngine's memory model is organized around allocation domains, lifetime classes, and deterministic GC observability rather than donor heap layout imitation. The traceability anchors are Plan section 10.3 (allocation domains + deterministic GC mode), section 10.11 (resource bounds and guardrails), and thesis requirements for replayable high-impact decisions. The model separates runtime object memory, extension-cell memory, evidence-buffer memory, and control-plane metadata memory into distinct domains with explicit ownership and accounting rules. This prevents ambient authority leakage across subsystems and enables policy-aware memory governance.

Lifetime classes are explicit: ephemeral parse/lower buffers, request-scoped execution allocations, session-scoped caches, and durable evidence/log artifacts. Each class has deterministic cleanup semantics and bounded retention policies. GC behavior is designed for reproducibility first, then latency optimization: a deterministic test mode provides stable collection checkpoints and event ordering for conformance/replay gates. Production mode can include adaptive heuristics, but any heuristic must degrade to deterministic policy-safe behavior under replay or safety-twin evaluation. Pause-time instrumentation is part of the architecture contract, not an afterthought, because memory control participates in containment and operational SLOs.

The model rejects direct adoption of donor GC algorithms, donor object header layouts, and donor inter-generational optimization assumptions as architecture dependencies. Instead, object representation is tailored to FrankenEngine's execution-slot and policy metadata requirements, including per-object lineage tags where needed for evidence correlation. Memory pressure signals are integrated with policy controllers so severe pressure can trigger deterministic degraded-mode behavior instead of silent semantic drift.

The result is a memory subsystem that supports compatibility semantics while preserving FrankenEngine priorities: deterministic replayability, policy-correct containment behavior under stress, and auditable resource accounting across untrusted extension workloads.

## 5. Execution Model

Execution is synthesized around typed execution slots, capability-bounded cells, and explicit promotion/demotion workflows for native replacement. This traces to Plan section 10.2 (slot registry contracts), section 10.5 (extension host security path), section 10.9 (GA native lane release gates), and section 10.15 (verified self-replacement architecture). The model assumes that any delegated behavior is transitional and explicitly constrained; GA lanes must converge to fully native slot ownership with signed lineage and no hidden fallback.

Each slot has a stable identity, semantic boundary, authority envelope, and promotion state. Execution-lane routing is deterministic and policy-visible; route reasons are emitted as structured metadata. Delegate cells, where present, are treated as untrusted execution contexts subject to the same capability checks, evidence obligations, and revocation semantics as third-party extensions. Promotion to native implementations requires conformance parity, signature-verified lineage artifacts, and gate checks proving delegate fallback is unreachable in GA configuration.

The scheduler is designed for reproducibility: queue ordering, microtask checkpoints, and hostcall boundary transitions emit replay-stable events with deterministic IDs. Failure semantics are typed and serializable so incident bundles can reconstruct decision sequences exactly. Cross-lane state interactions are mediated by explicit contracts rather than implicit shared internals, reducing the risk of architecture drift and hidden compatibility shims.

This model intentionally avoids donor-style hidden execution tiers and opaque runtime shortcuts. FrankenEngine execution is a policy-governed, evidence-emitting pipeline where every high-impact decision can be replayed and audited without reverse engineering internal heuristics. That architecture is essential for adversarial extension operations and for constitutional claims about native ownership and auditable autonomy progression.

## 6. Optimization Strategy

FrankenEngine optimization is proof-grounded specialization, not speculative donor-JIT mimicry. Traceability anchors include Plan section 9I.5 (policy theorem checks), section 10.15 (proof-specialized lanes), section 5.1 (profile-driven optimization discipline), and section 5.2 (equation-backed decisions). Optimizations are admitted only when they preserve semantic equivalence, remain within policy/legal authority envelopes, and attach rollback artifacts. This policy creates an optimization system that compounds security proofs into performance gains instead of trading one for the other.

The optimization lifecycle is explicit: baseline measure, hotspot profiling, candidate transform synthesis, proof obligation generation, translation-validation checks, staged activation, and continuous drift monitoring. Candidate transforms include hostcall dispatch specialization under proven capability attenuation, IFC-check elision in proof-safe regions, and fused instruction motifs derived from replay-stable legal sequences. Every admitted transform is accompanied by an optimization receipt linking input proofs, transformed IR hash, equivalence evidence, validity epoch, and rollback token.

Uncertainty is treated as a first-class signal. If posterior uncertainty or theorem coverage drops below threshold, the optimizer fails closed to unspecialized legal paths. This supports deterministic safe mode and prevents opaque speculative behavior from bypassing security contracts. Performance claims are evidence-bound: no optimization claim is published without reproducible artifacts and replay checks.

This synthesis explicitly rejects donor optimization architecture as a template. We do not import donor feedback-vector ecosystems, donor IC stub hierarchies, or donor speculative deopt pipelines as requirements. Instead, we use FrankenEngine-native proof contracts and policy state to drive optimization legality. The expected output is a runtime that can improve throughput while increasing assurance, with each optimization step explainable and reversible under audit.

## 7. Non-Goals (Explicit Donor Architecture Exclusions)

The following architecture patterns are intentionally not adopted. These exclusions are binding design constraints.

1. `NG-001`: donor hidden-class/shape layout replication.
Reason: semantic compatibility does not require object layout cloning and this would couple core internals to donor assumptions.

2. `NG-002`: donor inline-cache hierarchy replication.
Reason: cache strategy is an optimization concern; FrankenEngine uses proof-legal specialization gates instead.

3. `NG-003`: donor optimizer pipeline stage mirroring.
Reason: pipeline ownership must align with IR2/IR3 proof contracts, not donor pass decomposition.

4. `NG-004`: donor bytecode format adoption.
Reason: FrankenEngine IR contracts are canonical and evidence-linked; donor bytecode is out-of-contract.

5. `NG-005`: donor garbage-collector algorithm transplantation.
Reason: deterministic replay obligations require GC observability semantics not guaranteed by donor algorithms.

6. `NG-006`: donor object-header memory layout adoption.
Reason: FrankenEngine requires policy/evidence metadata integration absent in donor headers.

7. `NG-007`: donor scheduler architecture duplication.
Reason: microtask/event ordering must be policy-auditable with deterministic event IDs.

8. `NG-008`: donor speculative JIT/deopt choreography reuse.
Reason: optimization legality is theorem/proof gated with explicit rollback artifacts.

9. `NG-009`: donor feedback-vector semantics as architecture dependency.
Reason: optimization triggers must remain interpretable in trust-economics and policy terms.

10. `NG-010`: donor parser staging and preparse internals.
Reason: parser design is driven by canonical AST/replay requirements.

11. `NG-011`: donor exception fast-path shortcuts with opaque side effects.
Reason: deterministic error taxonomy and replay require explicit propagation rules.

12. `NG-012`: donor host embedding APIs as core runtime pathways.
Reason: violates native-only ownership and split-contract constraints.

13. `NG-013`: hidden delegate fallback in GA default lanes.
Reason: section 10.9 release gates require zero mandatory delegates in GA lanes.

14. `NG-014`: implicit compatibility shims bypassing policy visibility.
Reason: compatibility behavior must remain typed, explicit, and auditable.

15. `NG-015`: donor internal telemetry schema reuse.
Reason: FrankenEngine telemetry keys are standardized for policy/replay evidence.

16. `NG-016`: donor concurrency primitives as a mandated runtime model.
Reason: runtime concurrency must be selected by deterministic scheduling and containment requirements.

17. `NG-017`: donor module-loader internals as design defaults.
Reason: module semantics are required; loader architecture remains native and policy-hooked.

18. `NG-018`: donor memory-tier heuristics as immutable policy.
Reason: resource strategy must integrate with FrankenEngine guardrails and revocation policies.

## 8. Thesis Justification Matrix

This matrix links architecture decisions to thesis goals and plan anchors.

Architecture synthesis review artifacts must continue to emit stable audit keys to remain compatible with the broader policy/replay evidence plane:
- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`

| Architectural Choice | Security Thesis | Performance Thesis | Determinism Thesis | De Novo Ownership Thesis | Plan Anchors |
|---|---|---|---|---|---|
| Arena recursive-descent parser + canonical AST | prevents parser ambiguity-induced policy blind spots | lowers allocation overhead in parse phase | stable AST hashes for replay | parser internals are native-owned | §4.1, §10.2 parser trait |
| Five-level IR (`IR0..IR4`) with policy/proof layers | capability + IFC checks encoded in IR2 | specialization admitted via IR3 evidence | pass witnesses make lowering reproducible | rejects donor bytecode architecture coupling | §10.2 IR contracts, §9A.7 |
| Allocation domains + deterministic GC mode | isolates untrusted extension memory effects | targeted memory budgets by domain | deterministic collection checkpoints in replay mode | avoids donor heap model dependence | §10.3, §10.11 |
| Typed execution slots with promotion gates | prevents silent authority expansion through delegates | enables prioritized native replacement sequencing | route-reason metadata + gate receipts are stable | runtime core converges to native slot ownership | §10.2 slot registry, §10.9 |
| Proof-grounded specialization + rollback receipts | optimization cannot bypass policy legality | security proofs become optimization accelerants | fallback path deterministic on uncertainty | optimizer semantics native to FrankenEngine | §5.1, §9I.5, §10.15 |
| Structured audit key contract | enables incident-grade traceability | reduces debugging latency and operator ambiguity | stable event schema supports deterministic replays | telemetry contract owned by engine constitution | §5.2, §10.12 |

The synthesis pattern across all rows is consistent: donor semantics are treated as behavioral requirements, while design mechanisms are chosen to satisfy FrankenEngine's own constitutional and technical constraints. This preserves compatibility value without importing donor architecture debt. It also creates a clean dependency chain for subsequent beads: `bd-j7z` can operationalize parity tracking against semantic IDs, and VM Core implementation beads can map code deliverables directly to architecture choices documented here. The matrix should be used as a review gate for architecture-affecting pull requests: if a proposed design cannot be mapped to at least one thesis column and one plan anchor, it is not ready for acceptance.

## 9. Verification Runbook

1. Run structural validation suite:

```bash
./scripts/run_frankenengine_native_synthesis_suite.sh ci
```

2. Inspect generated artifacts:

```bash
ls -la artifacts/frankenengine_native_synthesis/
cat artifacts/frankenengine_native_synthesis/<timestamp>/run_manifest.json
cat artifacts/frankenengine_native_synthesis/<timestamp>/frankenengine_native_synthesis_events.jsonl
```

3. Verify plan linkage:

```bash
rg -n "FrankenEngine-native architecture synthesis" PLAN_TO_CREATE_FRANKEN_ENGINE.md
```

4. Verify semantic donor spec linkage:

```bash
rg -n "SEMANTIC_DONOR_SPEC.md" docs/architecture/frankenengine_native_synthesis.md
```
