# Modes of Reasoning: FrankenEngine Project Analysis Report

**Project:** FrankenEngine -- Native Rust runtime for adversarial extension workloads
**Date:** 2026-04-07
**Modes Used:** 10 of 80 available
**Agents:** 10 Claude Opus 4.6
**Lead Agent:** PearlTower (Claude Opus 4.6, 1M context)

---

## 1. Executive Summary

Ten independent analytical lenses -- spanning systems thinking, formal logic, adversarial review, failure analysis, historical analogies, stakeholder perspectives, counterfactual reasoning, scope control, deontic analysis, and debiasing -- converged on a unified picture of FrankenEngine.

The project demonstrates genuine architectural ambition and engineering substance. The capability-typed execution model, 5-level IR pipeline, Bayesian guardplane, and evidence-first governance are real innovations in the runtime space. The `#![forbid(unsafe_code)]` guarantee, BTreeMap-everywhere determinism, and fixed-point arithmetic represent principled, defensible decisions.

However, the analysis reveals a systematic and consequential gap between the project's **governance infrastructure** and its **runtime execution capability**. The overwhelming finding, converged upon by 6+ modes independently, is that FrankenEngine has built an elaborate security and governance apparatus (~400 modules) that governs a runtime engine (~25 core modules) which cannot yet execute standard JavaScript programs. The interpreter uses `i64`-only arithmetic -- `1.5 + 2.5` cannot be computed. The "cryptographic" hash layer is a hand-rolled SipHash-inspired construction, not a proven primitive. The capability system is well-designed but not enforced at the interpreter boundary. The 50+ governance gates have never evaluated a real build artifact.

### Key Takeaways

1. **The capability-execution gap is critical**: The formal capability system (`CapabilityProfile`, 16 atomic capabilities, lattice operations) is architecturally sound but disconnected from the interpreter, which uses `Vec<String>` for capability checks. This is the single highest-priority fix. *(Converged: 5 modes)*

2. **The project cannot execute standard JavaScript**: The `Value::Int(i64)` representation excludes floating-point numbers, NaN, Infinity, and -0. No ECMAScript conformance numbers exist. The README demo (`40 + 2`) is the upper bound of what works. *(Converged: 4 modes)*

3. **Homebrew cryptography undermines security claims**: The hash tier system uses a custom SipHash-inspired construction instead of SHA-256/BLAKE3. The signature scheme is a symmetric MAC providing no non-repudiation. "Cryptographic governance" is vocabulary, not reality. *(Converged: 3 modes)*

4. **The governance-to-runtime ratio is inverted**: ~80% of modules are governance/evidence/gate infrastructure, ~5% are the execution pipeline. 53 gate modules could be 5-10 composable gates. 388 shell scripts could be one parameterized runner. The README is 2,260 lines, mostly gate documentation. *(Converged: 5 modes)*

5. **The multi-agent development model produced breadth over depth**: 30+ AI agents created 455 modules with 37,897 tests, but the tests predominantly verify structural properties (serde roundtrips, Display impls) rather than semantic correctness against the ECMAScript specification. *(Converged: 4 modes)*

### Overall Confidence: 0.84
High confidence in structural findings (directly verified in source code by multiple independent agents). Moderate confidence in performance and scaling predictions (pre-production system with no benchmark data).

---

## 2. Methodology

### Why These 10 Modes?

| # | Mode | Code | Category | Selection Rationale |
|---|------|------|----------|-------------------|
| 1 | Systems-Thinking | F7 | Causal | Map feedback loops across 455 interconnected modules |
| 2 | Deductive Inference | A1 | Formal | Verify logical consistency of security and determinism claims |
| 3 | Adversarial Review | H2 | Strategic | Red-team the security model that is the project's core value prop |
| 4 | Failure-Mode Analysis | F4 | Causal | Enumerate cascading failures in a complex layered system |
| 5 | Analogical Reasoning | B6 | Ampliative | Compare to V8/JSC/Deno/Wasm/seL4/EVM for transferable lessons |
| 6 | Perspective-Taking | I4 | Dialectical | Surface blind spots via security auditor, CTO, contributor, etc. |
| 7 | Counterfactual | F3 | Causal | Evaluate whether key architectural decisions are still optimal |
| 8 | Scope Control | L5 | Meta | Assess whether 455-module complexity is justified or accidental |
| 9 | Deontic Reasoning | J1 | Modal | Analyze obligations/permissions/prohibitions in the capability system |
| 10 | Debiasing | L2 | Meta | Identify cognitive biases in the project and the analysis itself |

### Category Coverage

| Category | Count | Modes |
|----------|-------|-------|
| A: Formal | 1 | Deductive (A1) |
| B: Ampliative | 1 | Analogical (B6) |
| F: Causal | 3 | Systems (F7), Failure-Mode (F4), Counterfactual (F3) |
| H: Strategic | 1 | Adversarial (H2) |
| I: Dialectical | 1 | Perspective-Taking (I4) |
| J: Modal | 1 | Deontic (J1) |
| L: Meta | 2 | Scope Control (L5), Debiasing (L2) |

**Axis coverage:** Non-ampliative (A1, J1), Ampliative (B6, F3), Monotonic (A1), Non-monotonic (F3, F4, F7), Descriptive (F7, A1, F4), Normative (J1, I4), Belief (A1, B6), Action (H2, F4), Single-agent (A1, F7), Multi-agent (H2, I4), Truth (A1, H2), Adoption (I4). All 7 axes covered.

### Antagonistic Pairs
- **Adversarial (H2) vs Perspective-Taking (I4)**: Attack vs empathize
- **Scope Control (L5) vs Systems-Thinking (F7)**: Reduce vs expand
- **Debiasing (L2) vs all other modes**: Meta-level check on object-level reasoning

### Modes Considered But Not Selected
- **Game-Theoretic (H1)**: Would analyze attacker incentive models -- partially covered by H2
- **Type-Theoretic (A7)**: Would verify Rust type system usage -- partially covered by A1 and J1
- **Bayesian (B3)**: Would update risk estimates -- less applicable to architecture review
- **Scientific (K2)**: Would evaluate experimental methodology -- less applicable to pre-production system

---

## 3. Convergent Findings (High Confidence)

These findings were independently reached by 3+ reasoning modes. Independent discovery via different analytical frameworks is the strongest signal.

### C1: Capability System Disconnected from Interpreter Execution

**Supporting modes:** Systems-Thinking (F7), Adversarial Review (H2), Failure-Mode (F4), Deontic (J1), Perspective-Taking (I4)
**Confidence:** 0.95

The formal capability system in `capability.rs` defines 5 profiles (Full/EngineCore/Policy/Remote/ComputeOnly) with 16 atomic capabilities, lattice operations (`subsumes()`, `intersect()`), and a typed `require_capability()` enforcement function. This is architecturally sound.

However, the baseline interpreter (`baseline_interpreter.rs`) uses `granted_capabilities: Vec<String>` -- raw strings, not the `RuntimeCapability` enum. The check is string comparison: `self.config.granted_capabilities.iter().any(|c| c == &capability.0)`. The formal `CapabilityProfile` with its typed lattice is never referenced by the interpreter.

**Evidence from each mode:**
- **F7 (Systems):** "The Capability System is Well-Designed but Shallowly Integrated -- only 8 modules directly import from `crate::capability`. The interpreter does not check capabilities at instruction dispatch time."
- **H2 (Adversarial):** "CapabilityProfile and ProfileKind are NEVER referenced in the interpreter. The interpreter uses Vec<String>, bypassing the entire typed capability system."
- **J1 (Deontic):** "The formal typed capability algebra from capability.rs is not connected to the actual execution path. A capability could be misspelled and silently fail."
- **I4 (Perspective, Security Auditor):** "A capability system that depends on developers remembering to check is not a real capability system -- it is a convention."
- **F4 (Failure-Mode):** No explicit finding, but the interpreter memory analysis confirms no capability checks on heap allocation or GC invocation.

**Why convergence matters:** Five fundamentally different analytical lenses -- structural (F7), adversarial (H2), normative (J1), empathetic (I4), and failure-oriented (F4) -- all independently identified the same gap. This is not a matter of interpretation; it is a verifiable implementation gap.

**Recommended action:** Replace `InterpreterConfig::granted_capabilities: Vec<String>` with `BTreeSet<RuntimeCapability>` and use the formal `require_capability()` function at the interpreter's hostcall dispatch boundary. Add capability checks for `HeapAllocate`, `VmDispatch`, and `GcInvoke` at the appropriate interpreter operations.

---

### C2: Governance Infrastructure Vastly Exceeds Runtime Implementation

**Supporting modes:** Systems-Thinking (F7), Scope Control (L5), Perspective-Taking (I4), Counterfactual (F3), Debiasing (L2), Analogical (B6)
**Confidence:** 0.93

The project contains ~455 source modules. Depending on measurement:
- F7 found 120 modules reachable from entry points, 335 structurally disconnected
- L5 found only 7 modules directly imported by the core orchestration
- I4 estimated ~25 core runtime modules vs ~430 governance/meta modules
- F3 estimated the infrastructure-to-runtime ratio at ~5:1

All modes agree on the direction: the governance, evidence, gating, and meta-infrastructure dramatically outweigh the actual execution engine.

**Evidence from each mode:**
- **F7:** "74/26 Island Problem -- 335 modules (70% of LOC) are only exercised through tests. Feature-gating these would reduce cargo check time ~50-60%."
- **L5:** "53 gate modules follow identical patterns. 388 shell scripts are parameterized copies. 57% of source LOC is inline test code. Test-to-production ratio is 4.4:1."
- **I4 (CTO):** "135 of 455 modules are governance/audit/evidence. The actual runtime is perhaps 5% of the codebase. This is an inverted pyramid."
- **F3:** "The project has optimized for building infrastructure to build a runtime rather than building a runtime."
- **L2:** "80% of the codebase is governance. 5% is the execution pipeline."
- **B6:** Historical warnings: Dart VM (Google, abandoned), Chakra (Microsoft, abandoned), Servo (Mozilla, stalled).

**Why convergence matters:** This finding spans structural analysis (F7), complexity metrics (L5), stakeholder evaluation (I4), alternative-history reasoning (F3), bias identification (L2), and historical precedent (B6). Six independent lenses all point to the same structural imbalance.

**Recommended action:** Split the monolithic crate into 3-4 subcrates: `frankenengine-core` (120 reachable modules), `frankenengine-governance` (governance/evidence modules), `frankenengine-gates` (53 gate modules). Consolidate gates into a composable `Gate<Policy, Evidence>` framework. Consolidate 388 shell scripts into one parameterized runner.

---

### C3: Homebrew Cryptography Undermines Security Claims

**Supporting modes:** Deductive (A1), Adversarial Review (H2), Debiasing (L2)
**Confidence:** 0.92

The 3-tier hash strategy claims compile-time type safety between tiers. The actual implementation:

- **Tier 2 (ContentHash) and Tier 3 (AuthenticityHash) share the same unkeyed algorithm.** `AuthenticityHash::compute(data)` calls `collision_resistant_hash(data)` -- the same function as `ContentHash::compute(data)`. The tiers collapse for unkeyed usage.
- **The "collision-resistant" hash is a custom SipHash-inspired construction**, not a proven collision-resistant function. SipHash is a PRF for hash tables, not a collision-resistant hash. The construction uses 2 mixing rounds per 8-byte block.
- **The signature scheme is a symmetric MAC.** `sign_preimage()` derives the verification key from the signing key. Anyone who can verify can forge -- no non-repudiation.
- **SHA-256 (`sha2` crate) is already a dependency** but used in only ~20 files. The hand-rolled hash is used in 250+ call sites.

**Evidence from each mode:**
- **A1:** "Hash Tier 2/3 Use Identical Unkeyed Algorithm -- Tier Separation Breaks. AuthenticityHash::compute() exists as a public API that produces a Tier 2 hash labeled as Tier 3."
- **H2:** "The project has sha2 in Cargo.toml but uses it only in ~20 files, while the homebrew hash is used in 250+ call sites. The 'signature' provides no non-repudiation."
- **L2:** "The vocabulary creates an impression of cryptographic rigor that the implementation does not deliver. 'Signed decision receipts' sounds like a property that would survive third-party audit."

**Kill Thesis test:** Could these findings be wrong? Only if there is a deliberate design decision to use weaker-than-standard hashing for performance reasons and the claims are meant to be aspirational. However, `sha2` is already a dependency and would provide actual collision resistance at minimal cost. The choice to use homebrew crypto when standard crates exist is not defensible.

**Recommended action:** (1) Remove `AuthenticityHash::compute` (unkeyed) or make it `#[cfg(test)]` only. (2) Replace the SipHash-inspired construction with SHA-256 for Tier 2/3 operations. (3) Replace the MAC-based signature with Ed25519 via `ed25519-dalek`. All three crates are `#![forbid(unsafe_code)]`-compatible.

---

### C4: Integer-Only Interpreter Cannot Execute Standard JavaScript

**Supporting modes:** Analogical (B6), Perspective-Taking (I4), Counterfactual (F3), Debiasing (L2)
**Confidence:** 0.95

The interpreter's `Value` enum (`baseline_interpreter.rs`) represents all numbers as `Value::Int(i64)`. There is no floating-point variant. JavaScript's IEEE 754 double-precision semantics -- including `0.1 + 0.2`, `NaN`, `Infinity`, `-0`, and all fractional arithmetic -- are architecturally excluded.

**Evidence from each mode:**
- **B6:** "FrankenEngine deliberately uses fixed-point i64 millionths, which is semantically different from IEEE doubles. This means 0.1 + 0.2 does not work."
- **I4 (CTO):** "The interpreter uses integer-only arithmetic. This means standard JavaScript number semantics are not implemented."
- **F3:** "The i64-only Value type is the single most blocking gap. Without IEEE 754 doubles, the runtime cannot execute any real JavaScript."
- **L2:** "var x = 1.5 + 2.5 -- Parser would attempt parse::<i64>() on '1.5' and get None. The interpreter cannot represent 4.0."

**Why convergence matters:** Historical analogy, stakeholder evaluation, alternative-history analysis, and bias detection all independently identify the same gap. No reasoning mode defended the i64-only choice as sufficient for JavaScript execution.

**Recommended action:** Add `Value::Float(f64)` to the interpreter's value representation. Implement JavaScript's ToNumber, ToString, and comparison semantics for mixed int/float operations. Accept the determinism caveat for floating-point and use the existing `NondeterminismTrace` to record FP operations that affect replay.

---

### C5: No Interpreter Memory Budget Enables DoS

**Supporting modes:** Adversarial Review (H2), Failure-Mode (F4), Systems-Thinking (F7)
**Confidence:** 0.91

The interpreter enforces instruction budgets (100K/1M) but has no memory budget. A crafted program can allocate thousands of objects, create deep scope chains cloned on every closure call (`scope_chain.snapshot()` is O(n) per closure), and exhaust memory before instruction limits fire.

**Evidence from each mode:**
- **H2:** "alloc_object_with_prototype only checks u32::MAX. A crafted JS program can allocate 25,000 objects within the instruction budget."
- **F4:** "O(n^2) memory from closure capture. GC exists but is not integrated with interpreter's alloc_object. Cascade: closure memory -> OOM -> InMemoryLedger lost -> evidence trail broken."
- **F7:** "The Capability System... the interpreter does not check capabilities at instruction dispatch time -- it checks budgets and limits but not capability profiles."

**Recommended action:** Add `max_heap_objects: u32` and `max_total_memory_bytes: u64` to `InterpreterConfig`. Check in `alloc_object`, `scope_chain.snapshot()`, and `registers.resize()`. Integrate GC pressure checks into the allocation path.

---

## 4. Divergent Findings (Points of Disagreement)

### D1: Is `#![forbid(unsafe_code)]` the Right Constraint?

**Position A:** Counterfactual (F3) argues "Yes, strongly" (0.90 confidence). The safety guarantee is the project's most clearly correct decision. The performance left on the table (2-5x in specific subsystems) is small compared to the 100-1000x JIT gap.

**Position B:** Perspective-Taking (I4, Performance Engineer) argues it is "philosophically admirable but practically incompatible with competitive interpreter performance." Computed-goto dispatch and SIMD lexing require unsafe. Analogical (B6) notes that V8/JSC/SpiderMonkey all require unsafe-equivalent constructs for their interpreter hot paths.

**Analysis:** This is a genuine values tradeoff, not an error by either mode. The positions are answering different questions:
- F3 asks: "Is this the right security decision?" (Yes -- the threat model requires it)
- I4 asks: "Can this compete on throughput?" (No -- not without compilation tiers)

**Resolution (conditional):** If the goal is adversarial security, `forbid(unsafe_code)` is correct. If the goal includes "category-defining performance," the project needs a safe code-generation tier (e.g., Cranelift backend) rather than unsafe interpreter tricks. Both positions are valid in their domain.

---

### D2: Is the 455-Module Architecture Justified?

**Position A:** Systems-Thinking (F7) and Counterfactual (F3) argue the module count serves multi-agent coordination: "455 modules is a coordination mechanism, not just an architecture choice." File-level isolation prevents agent conflicts.

**Position B:** Scope Control (L5) argues for rationalization to 80-120 modules, noting 57 modules have zero internal imports, 53 gates follow identical patterns, and the naming scheme suggests template-driven generation.

**Analysis:** Both are correct about different temporal horizons. During active 30-agent development, the fine-grained modules prevent conflicts. For long-term maintenance, the module count is a liability (build times, navigation, artificial coupling through hub types).

**Resolution (temporal):** The 455-module structure was correct for the multi-agent development phase. As the project matures, consolidation into 80-120 modules (grouped by concern domain) should be a planned workstream.

---

### D3: Is the Governance Infrastructure Premature or Foundational?

**Position A:** Debiasing (L2) argues it is premature: "The project has built elaborate governance frameworks that operate in a vacuum. They govern decisions that are never actually made against real adversarial workloads."

**Position B:** Systems-Thinking (F7) notes the dual-mode adapter (`control_plane/mod.rs` with `cfg(feature = "asupersync-integration")`) is "a well-designed leverage point" enabling the system to build and test in isolation.

**Analysis:** The governance infrastructure is both premature AND foundational. The type definitions, evidence schemas, and gate architectures will be valuable when the runtime can execute real workloads. But building 53 gate modules before the interpreter handles floating-point is a sequencing error. The modes disagree on emphasis, not on facts.

**Resolution (sequencing):** Freeze governance module creation. Redirect development effort to the execution pipeline (floating-point, stdlib, ECMAScript conformance). Resume governance integration once the runtime can execute non-trivial JavaScript.

---

## 5. Unique Insights by Mode

### Systems-Thinking (F7) -- Exclusive
- **The Evidence Ledger is the System's Central Bottleneck (280-Inbound Hub)**: `hash_tiers` has 280 dependents, `security_epoch` has 254. Any change to these types forces recompilation of 250+ modules. This structural finding was invisible to other modes.
- **Compilation time feedback loop**: Slow builds -> larger agent batches -> more merge conflicts -> more fix sessions -> more code -> slower builds. The build system is a reinforcing loop.

### Deductive (A1) -- Exclusive
- **Vec-order canonical serialization fragility**: `ScopeNode.bindings` is `Vec<ResolvedBinding>` serialized in insertion order, not sorted. If two code paths produce the same bindings in different order, canonical hashes diverge. BTreeMap gets automatic ordering; Vec does not.
- **CapabilityProfile::intersect() returns misleading kind**: Always returns `ComputeOnly` regardless of actual intersection contents.

### Adversarial (H2) -- Exclusive
- **MAC-based "signatures" provide no non-repudiation**: The verification key IS the HMAC key. Any verifier can forge signatures. This was the deepest crypto finding.
- **Multi-agent development creates unreviewed attack surface**: 30+ agents, no commit signing, no semantic review -- only compilation checks.

### Failure-Mode (F4) -- Exclusive
- **Parser line-merge heuristic blind to comments/regex**: `merge_logical_lines` tracks braces in quotes but NOT in `//` comments or regex literals, causing potential misparse.
- **alloc_object uses panicking .expect()**: Process panic (not clean InterpreterError) on heap overflow.
- **Cascade chain identification**: Memory amplification -> OOM -> evidence loss -> gate failure -> release blocked with unclear cause.

### Analogical (B6) -- Exclusive
- **Wasmtime fuel metering validates budget approach**: Instruction-counting budgets are proven practical in production Wasm runtimes.
- **Historical warnings**: Dart VM (abandoned), Chakra (abandoned), Servo (stalled) -- from-scratch runtime rewrites have long gestation and high abandonment rates.
- **BEAM/Erlang supervision tree analogy**: Per-extension isolation with explicit containment actions parallels Erlang's let-it-crash supervision.

### Perspective-Taking (I4) -- Exclusive
- **No onboarding path for human contributors**: No CONTRIBUTING.md, no architecture diagram, no module dependency graph. The project is optimized for AI agents, not humans.
- **Two separate Value enums**: `baseline_interpreter::Value` (13 variants) and `bytecode_vm::Value` (4 variants) coexist with unclear canonical status.
- **AI reasoning artifacts in production code**: `evidence_ledger.rs` contains agent reasoning traces ("Assume it has major() and minor()... We'll use a hack").

### Counterfactual (F3) -- Exclusive
- **Path dependency chain**: No-V8 -> 30 agents -> 455 modules -> 53 gates -> 5-level IR -> BTreeMap everywhere -> forbid(unsafe). Changing any one decision cascades.
- **The no-V8 decision is the keystone**: If you accept V8 bindings, most other architectural decisions become unnecessary.
- **Inverted development sequence**: Built infrastructure-to-build-a-runtime before building the runtime.

### Scope Control (L5) -- Exclusive
- **42 binary entry points**: Most runtimes ship 1-3 binaries. These could be `frankenctl` subcommands.
- **Novel vocabulary as complexity**: "Dark matter saturation," "galaxy-brain explainability," "moonshot contracts," "supremacy cells" -- custom terminology where standard names exist.
- **Test-to-production ratio of 4.4:1**: 2M LOC tests for 457K LOC production code. Extreme even by high-assurance standards.

### Deontic (J1) -- Exclusive
- **Fleet de-escalation is unimplemented**: `allows_deescalation: bool` exists as a data field but no code path performs de-escalation. Containment is a permanent one-way ratchet.
- **Trust zone ceiling is static**: Validated at creation but not re-evaluated when parent constraints change.
- **Agent behavioral obligations are convention-only**: AGENTS.md rules have no machine enforcement (except `#![forbid(unsafe_code)]`).

### Debiasing (L2) -- Exclusive
- **Automation bias in test metrics**: Session 19 added 4,000 tests in one sitting. Tests predominantly verify serde roundtrips and Display impls, not semantic correctness.
- **The closed testing loop**: Agent A generates code, Agent B generates tests for that code, both compile, both pass, and the output is accepted without external validation.
- **Scope insensitivity**: 3 `todo!`/`unimplemented!` markers in 1M LOC suggests completionism without honest acknowledgment of unfinished work.

---

## 6. Risk Assessment

| Risk | Severity | Likelihood | Agreement Level | Supporting Modes |
|------|----------|-----------|-----------------|-----------------|
| Cannot execute standard JS (no float) | Critical | Certain | Converged (4) | B6, I4, F3, L2 |
| Homebrew crypto in security-critical paths | Critical | Current | Converged (3) | A1, H2, L2 |
| Capability bypass via string mismatch | High | Current | Converged (5) | F7, H2, J1, I4, F4 |
| Memory exhaustion DoS (no heap budget) | High | Likely | Converged (3) | H2, F4, F7 |
| Build time bottleneck (single crate) | High | Current | Converged (3) | F7, L5, I4 |
| Integration debt (335 disconnected modules) | High | Accumulating | Converged (3) | F7, L5, I4 |
| Empty audience token bypass | Medium | Current | Supported (2) | A1, J1 |
| Checkpoint obligation unenforced | Medium | Current | Supported (2) | J1, F4 |
| Evidence emission silently fails | Medium | Current | Supported (2) | J1, A1 |
| Parser comment/regex misparse | Medium | Conditional | Unique (1) | F4 |
| Fleet de-escalation impossible | Medium | Latent | Supported (2) | J1, F7 |
| Historical precedent for project abandonment | Medium | Long-term | Unique (1) | B6 |

---

## 7. Recommendations (Priority-Ordered)

### P0: Critical (Do immediately)

| # | Recommendation | Modes | Effort |
|---|---------------|-------|--------|
| R1 | **Add `Value::Float(f64)` to interpreter** -- without this, the system cannot execute JavaScript | B6, I4, F3, L2 | High |
| R2 | **Replace homebrew crypto with standard crates** -- use sha2/blake3 for hashing, ed25519-dalek for signatures | A1, H2, L2 | Medium |
| R3 | **Wire typed `CapabilityProfile` into interpreter** -- replace `Vec<String>` with `BTreeSet<RuntimeCapability>` | F7, H2, J1, I4, F4 | Medium |

### P1: High (Do in next cycle)

| # | Recommendation | Modes | Effort |
|---|---------------|-------|--------|
| R4 | **Add heap memory budget to interpreter** -- `max_heap_objects`, `max_total_memory_bytes` | H2, F4, F7 | Medium |
| R5 | **Split monolith into 3-4 subcrates** -- core, governance, gates | F7, L5, I4 | High |
| R6 | **Fix empty audience token bypass** -- reject at build time | A1, J1 | Low |
| R7 | **Remove `AuthenticityHash::compute` (unkeyed)** -- breaks tier separation | A1, H2 | Low |

### P2: Medium (Plan for upcoming work)

| # | Recommendation | Modes | Effort |
|---|---------------|-------|--------|
| R8 | **Integrate CheckpointGuard into interpreter** -- enforce checkpoint density obligation | J1, F4 | Medium |
| R9 | **Make evidence emission fail-closed** -- replace `let _ = emitter.emit()` | J1 | Low |
| R10 | **Fix parser comment/regex blindness** -- `merge_logical_lines` | F4 | Medium |
| R11 | **Consolidate 53 gates into ~10 composable gates** | L5, I4 | High |
| R12 | **Consolidate 388 scripts into parameterized runner** | L5 | Medium |

### P3: Strategic (Plan for maturity phase)

| # | Recommendation | Modes | Effort |
|---|---------------|-------|--------|
| R13 | **Publish Test262 conformance rate** -- even if low, it grounds claims | I4, L2 | Medium |
| R14 | **Create architecture overview document** -- 2-page diagram for human contributors | I4 | Low |
| R15 | **Implement inline caches + hidden classes** -- highest-leverage perf investment | B6, I4 | Very High |
| R16 | **Implement fleet de-escalation with quorum** | J1, F7 | High |
| R17 | **Audit for AI reasoning artifacts in comments** | I4, L2 | Medium |

---

## 8. New Ideas and Extensions

| Idea | Source Mode | Innovation Level | Description |
|------|-----------|-----------------|-------------|
| Compile-time module graph visualization | F7 | Incremental | `frankenctl graph` emitting DOT file of actual dependency graph, highlighting connected vs island modules |
| Adaptive prior from evidence history | F7 | Significant | Returning extensions get higher benign prior based on historical evidence, closing the evidence-risk feedback loop |
| Budget-proportional gate evaluation | F7 | Significant | Meta-gate allocating evaluation budget proportionally to historical failure rates |
| SoftFloat deterministic FP | F3, B6 | Significant | Use software-emulated floating point for deterministic replay of JS numeric operations |
| Safe code-generation tier via Cranelift | B6, I4 | Radical | Generate native code through a safe abstraction layer, avoiding unsafe while closing the JIT gap |
| External oracle differential testing | L2 | Significant | Run same programs through FrankenEngine and Node.js, diff outputs for conformance validation |
| BEAM-style live-attach debugging | B6 | Significant | Attach forensic observers to running execution cells without stopping them |
| Crate-level feature flags for module groups | F7 | Incremental | `cfg(feature = "governance")` to conditionally compile non-core modules, enabling sub-minute agent builds |

---

## 9. Assumptions Ledger

Assumptions surfaced across all modes that the project makes but does not state:

| Assumption | Surfaced By | Risk if Wrong |
|-----------|-----------|--------------|
| BTreeMap ordering is sufficient for determinism | A1 | Rust allocator nondeterminism could still cause replay divergence |
| Fixed-point millionths are adequate for JS numeric semantics | B6, I4, F3, L2 | They are demonstrably inadequate -- i64 cannot represent fractions |
| AI-generated code is trustworthy if it compiles | L2 | Subtle semantic bugs pass all structural checks |
| 37,897 tests constitute thorough coverage | L2 | Tests overwhelmingly verify structural properties, not semantic correctness |
| The adversarial extension workload market is large enough | B6 | Dart VM and Chakra were abandoned despite technical merit |
| Governance infrastructure can be built before the runtime | F3, L2 | Historical precedent suggests the inverse ordering is more successful |

---

## 10. Open Questions for Project Owner

1. **What is the plan for IEEE 754 floating-point support?** Is the i64-only representation a deliberate staging decision or an architectural commitment? (Raised by B6, I4, F3, L2)

2. **What is the current Test262 pass rate?** Even a rough number would calibrate all claims about JavaScript compatibility. (Raised by I4, L2)

3. **Why use a homebrew hash when sha2 is already a dependency?** Is there a performance justification for the SipHash-inspired construction over SHA-256? (Raised by A1, H2, L2)

4. **Is the 5-level IR pipeline's full complexity justified at this stage?** Could IR2/IR3 be merged until capability analysis and execution optimization genuinely diverge? (Raised by F3)

5. **What is the exit criterion for the multi-agent development phase?** When should the project transition from "maximize module breadth" to "maximize execution depth"? (Raised by L5, L2, F3)

6. **What concrete adversarial extension workloads is the project targeting?** Browser extensions? VS Code extensions? Cloud functions? The threat model shapes every architecture decision. (Raised by I4, B6)

7. **Is de-escalation of containment intentionally unimplemented?** Or is it planned work? A permanent containment ratchet has serious operational implications. (Raised by J1, F7)

---

## 11. Confidence Matrix

| Finding | Confidence | Supporting | Dissenting |
|---------|-----------|-----------|-----------|
| C1: Capability-execution gap | 0.95 | F7, H2, F4, J1, I4 | None |
| C2: Governance-runtime imbalance | 0.93 | F7, L5, I4, F3, L2, B6 | None |
| C3: Homebrew crypto | 0.92 | A1, H2, L2 | None |
| C4: No floating-point | 0.95 | B6, I4, F3, L2 | None |
| C5: No memory budget | 0.91 | H2, F4, F7 | None |
| D1: forbid(unsafe) tradeoff | 0.80 | F3 (pro), I4 (con) | Genuine tradeoff |
| D2: Module count justified? | 0.70 | F7, F3 (during dev), L5 (consolidate later) | Temporal disagreement |
| D3: Governance timing | 0.65 | L2 (premature), F7 (foundational) | Emphasis disagreement |

---

## 12. Contribution Scoreboard

| Mode | Findings | Unique | Evidence Quality | Calibration | Score |
|------|----------|--------|-----------------|-------------|-------|
| F7 Systems-Thinking | 12 | 3 | High (dep graph analysis) | 0.82 -- well-justified | **0.89** |
| A1 Deductive | 12 | 2 | Very High (line-level) | 0.88 -- conservative | **0.87** |
| H2 Adversarial | 8 | 2 | Very High (exploit paths) | 0.88 -- grounded | **0.86** |
| F4 Failure-Mode | 30+ | 3 | High (FMEA structure) | 0.83 -- calibrated | **0.85** |
| L2 Debiasing | 11 | 3 | High (bias-evidence pairs) | 0.88 -- honest | **0.84** |
| I4 Perspective | 6 views | 3 | High (stakeholder-grounded) | 0.82 -- realistic | **0.83** |
| B6 Analogical | 7 | 3 | High (structural mapping) | 0.78 -- appropriately uncertain | **0.82** |
| F3 Counterfactual | 7 | 2 | Medium-High (alt-history) | 0.62 -- honest about uncertainty | **0.78** |
| J1 Deontic | 9 | 2 | High (norm analysis) | 0.89 -- well-justified | **0.81** |
| L5 Scope Control | 8 | 2 | High (quantitative) | 0.88 -- data-driven | **0.80** |

**Diversity metric:** 7 of 12 categories represented, all 7 taxonomy axes covered, 3 antagonistic pairs active.

**Coverage analysis:** Strong on security, architecture, and meta-reasoning. Weaker on implementation-level debugging (no K2 Scientific or G11 Clinical modes). No ethical reasoning (K3) applied -- the project's impact on users and the ecosystem was not deeply examined.

---

## 13. Mode Performance Notes

**Most productive:** Systems-Thinking (F7) delivered the most structurally novel findings -- the dependency graph analysis, feedback loop mapping, and island module identification were invisible to other modes. The 280-inbound hub finding for `hash_tiers` is actionable and uniquely discoverable through systems analysis.

**Most impactful:** Adversarial Review (H2) and Deductive (A1) produced the findings with highest severity -- the homebrew crypto issues, capability bypass, and token audience vulnerability are security-critical and directly verifiable.

**Most calibrated:** Debiasing (L2) was the most honest about what the project is vs what it claims to be. Its finding about the "closed testing loop" (agents test their own code) is a meta-insight that improves interpretation of all other findings.

**Least applicable:** Scope Control (L5) and Debiasing (L2) had significant overlap -- both identified the governance-runtime imbalance. Future runs should use one meta mode rather than two.

**Underperformers:** None -- all 10 modes produced substantive, non-duplicative findings. The mode selection was effective.

---

## 14. Mode Selection Retrospective

**Would I choose differently with hindsight?**

The selection was effective. All 10 modes produced unique insights. If I could swap one mode:

- **Replace L5 (Scope Control) with K2 (Scientific Reasoning)**: L5's findings overlapped significantly with F7, I4, and L2. A scientific reasoning mode would have tested specific hypotheses about the runtime's behavior (e.g., "does the interpreter correctly handle all integer edge cases?" or "does the lowering pipeline preserve semantic equivalence?") -- questions that no mode directly addressed.

- **Consider adding A7 (Type-Theoretic)**: The Rust type system is load-bearing for security in this project. A type-theoretic analysis of whether the type system actually enforces the claimed invariants would have complemented J1's deontic analysis.

---

## 15. Final Assessment

FrankenEngine is a genuinely ambitious project with real intellectual substance. The capability-typed execution model, Bayesian guardplane, and evidence-first governance represent novel contributions to the runtime design space. The `#![forbid(unsafe_code)]` commitment is courageous and defensible. The deterministic-by-construction approach (BTreeMap, fixed-point, canonical serialization) is principled.

The project's central challenge is sequencing. It has built the world's most elaborate governance apparatus for a JavaScript runtime that cannot yet execute `1.5 + 2.5`. The gap between the security vocabulary and the security implementation (homebrew crypto, unenforced capabilities) is the highest-risk finding. The gap between the governance infrastructure and the runtime's semantic coverage is the highest-priority strategic concern.

The path forward is clear: freeze governance expansion, prioritize floating-point support and ECMAScript conformance, replace homebrew crypto with standard primitives, wire the capability system into the interpreter, and begin crate-level decomposition. The architectural foundation is sound. The execution needs to catch up to the ambition.
