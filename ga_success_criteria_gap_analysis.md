# GA Success Criteria vs Current Reality Gap Analysis

## Summary
The plan's Section 13 success criteria assume a lane-based architecture with delegate cells as separate execution engines that need elimination for GA. The current implementation has lane infrastructure but uses a unified native interpreter, creating a fundamental mismatch between plan assumptions and implementation reality.

## Plan Requirements (Section 13)

The plan states GA success requires:
- **Line 1291**: "native execution lanes run without external engine bindings"  
- **Line 1329**: "GA default lanes run with zero mandatory delegate cells for core runtime slots"
- **Line 1067**: "GA default lanes are fully native (0 mandatory delegate cells), with complete signed replacement lineage for all formerly delegated core slots"

**Plan Architecture Assumption**: The success criteria assume:
1. Execution happens in "lanes" that can be either native or delegate  
2. Delegate cells represent external engine dependencies (performance limitation)
3. GA requires promoting all delegate cells to native implementations
4. This promotion needs signed replacement receipts proving equivalence

## Current Implementation Reality

### Lane Architecture Analysis
**Source**: `crates/franken-core/src/baseline_interpreter.rs`

Current LaneRouter has two lanes:
- **QuickJsLane**: "Deterministic baseline-interpreter profile"
- **V8Lane**: "Throughput-tuned baseline-interpreter profile"

**Key Finding**: Both lanes use **identical execution logic** via `InterpreterCore`:
```rust
// Both QuickJsLane and V8Lane execute_with_hook methods:
let mut core = InterpreterCore::new(self.config.clone(), trace_id);
```

**From line 17-19 comment**:
> "Both profiles share the same `InterpreterCore` execution logic; the profile difference is in policy (instruction budget, register limit, dispatch strategy), not in a second engine backend."

### Delegate Cell Analysis  
**Source**: `crates/franken-core/src/execution_cell.rs`

Current delegate cells are **execution tracking units**, not separate engines:
- `CellKind::Extension` - hosts loaded extensions
- `CellKind::Session` - hosts sessions within extensions  
- `CellKind::Delegate` - hosts delegate computations

**Key Finding**: Delegate cells are organizational/tracking constructs, not performance bottlenecks requiring elimination.

### External Engine Binding Analysis
**Finding**: **ZERO external engine bindings exist**
- V8Lane name is misleading - it doesn't use V8 engine
- No FFI to Node, Bun, V8, or other external JavaScript engines
- All execution happens via native `InterpreterCore` 

## The Fundamental Gap

| Plan Assumption | Current Reality |
|-----------------|-----------------|
| Delegate cells = external engine dependency | Delegate cells = execution tracking only |
| V8Lane = external V8 engine binding | V8Lane = native interpreter with V8-like config |
| GA requires delegate→native promotion | Already 100% native execution |
| Need signed replacement receipts | No external engines to replace |

## Resolution Options

### Option 1: Update Success Criteria (Recommended)
**Rationale**: The current implementation already achieves the plan's **intended** goal (native execution without external dependencies) but doesn't match the **literal** criteria.

**Required Changes**:
1. Replace "zero mandatory delegate cells" with "100% native execution"
2. Remove references to delegate→native promotion receipts  
3. Clarify that execution profiles (QuickJs/V8) are configuration variants, not engine bindings
4. Update Section 13 language to match current hybrid-native architecture

### Option 2: Implement Full Lane Architecture  
**Rationale**: Build the architecture the plan actually describes.

**Required Implementation**:
1. Create actual external engine bindings (V8, Node.js)
2. Make delegate cells represent external execution environments
3. Implement delegate→native promotion with replacement receipts
4. Build lane selection policy that can choose between native/external engines

**Cost**: ~6+ months major architectural work, external dependencies, FFI complexity

### Option 3: Rename Current Architecture
**Rationale**: Keep current implementation but rename to match plan vocabulary.

**Required Changes**:
1. Rename V8Lane to ThroughputNativeLane 
2. Remove all delegate cell terminology where it means "tracking units"
3. Use "native profile" instead of "lane" terminology
4. Update all documentation to avoid misleading names

## Recommendation

**Choose Option 1: Update Success Criteria**

The current implementation is architecturally sound and achieves the security/performance goals the plan intended. The gap is in terminology and success criteria language, not in missing core functionality.

**Proposed Success Criteria Revision**:
- ✅ "FrankenEngine executes JavaScript using native interpreter without external engine bindings"
- ✅ "Multiple execution profiles (deterministic/throughput) available via configuration"  
- ✅ "All core runtime slots implemented natively in Rust"
- ❌ ~~"GA default lanes run with zero mandatory delegate cells"~~
- ❌ ~~"complete signed replacement lineage for all formerly delegated core slots"~~

This preserves the plan's security and performance intentions while matching implementation reality.

---

## 2026-05-01 Reality-Check Follow-Through

This section records the follow-through from applying `$reality-check-for-project`
to the current repository state. It is intentionally operational: every claim is
either tied to evidence, downgraded to an open proof gap, or linked to a tracker
item that must close before stronger public language is justified.

### Verification Snapshot

- Repo rules rechecked: branch is `main`; Cargo-only validation applies; no file
  or folder deletion is allowed without explicit user approval; significant
  claims require reproducible artifacts.
- Claim sources inspected: `README.md`, `PLAN_TO_CREATE_FRANKEN_ENGINE.md`,
  `docs/RUNTIME_CHARTER.md`, current source modules, examples, and current `br`
  backlog.
- Current dirty worktree caveat: Rust, test, generated-fixture, and scratch-file
  edits were already present when this follow-through ran. This pass did not
  modify those source/test/generated files.
- Focused compile-health check passed on 2026-05-01:
  `timeout 600 env CARGO_INCREMENTAL=0 RUSTFLAGS='-C linker=cc' cargo check -p frankenengine-engine --tests`
  completed successfully in 8m10s.
- This is not a release gate substitute. Because this pass only changes docs and
  tracker metadata, it did not run the full `cargo check --all-targets`,
  `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`, or
  `cargo test` suite.

### Status Legend

| Status | Meaning |
|---|---|
| `LIVE-CHECKED` | A current command or source path was checked in this pass. |
| `IMPLEMENTED-NOT-PROVEN` | Real code exists, but the public claim needs a fresh artifact/gate before stronger wording is allowed. |
| `STATIC-FIXTURE-RISK` | Evidence currently appears to validate checked-in fixtures more than live runtime behavior. |
| `SPEC-OR-PLAN-ONLY` | A spec, design, or broad epic exists, but no current proof artifact was verified in this pass. |
| `BLOCKED-BY-PROOF-GAP` | The claim must stay `target` or `hypothesis` until the linked bead closes. |

### Granular TODO Ledger

| State | Item | Owner/Tracker | Completion requirement |
|---|---|---|---|
| Done | Re-read repo instructions and mission constraints. | This pass | `main` branch confirmed; Cargo-only and no-deletion constraints recorded. |
| Done | Compare README/PLAN claim language against implementation and evidence posture. | This pass | High-impact claims listed in the matrix below. |
| Done | Check existing tracker state for duplicate proof-gap work. | This pass | Existing open/claimed benchmark, CLI, React, and RGC tasks reviewed before creating new beads. |
| Done | Verify the previous timer compile blocker is not currently reproducing. | This pass | Focused `cargo check -p frankenengine-engine --tests` passed. |
| Done | Create a live claim-matrix gate task. | `bd-1qkrc` | Bead created with acceptance criteria for claim scope, artifact handles, freshness, commands, and downgrade reports. |
| Done | Create a static-fixture replacement task for security examples. | `bd-2wf47` | Bead created with acceptance criteria for live runtime/CLI proof paths. |
| Done | Create a disruptive-floor metric gate task. | `bd-x7nod` | Bead created and linked to prerequisites for matrix and live security proof work. |
| Done | Create a README CLI workflow smoke task. | `bd-3tsah` | Bead created with acceptance criteria for version/compile/verify/run/replay artifact linkage. |
| Open | Implement the claim-to-proof matrix gate. | `bd-1qkrc` | Checked-in matrix plus deterministic scanner fails on unsupported observed/superiority wording. |
| Open | Enumerate every high-impact README and PLAN claim. | `bd-1qkrc` | Rows cover README TL;DR, CLI Contract, PLAN disruptive floor, and impossible-by-default index. |
| Open | Add allowed wording state to each claim row. | `bd-1qkrc` | Each row declares `observed`, `target`, or `hypothesis` under `docs/RUNTIME_CHARTER.md`. |
| Open | Add artifact handles and verification commands to each row. | `bd-1qkrc` | Missing proof must be explicit, not implied. |
| Open | Emit exact downgrade wording when proof is absent. | `bd-1qkrc` | Gate output is actionable enough to patch docs in the same change set. |
| Open | Convert revocation/quarantine/IFC/capability examples from static proof to live proof. | `bd-2wf47` | Scripts invoke real runtime or CLI paths and compare generated artifacts. |
| Open | Preserve static fixtures only as expected outputs. | `bd-2wf47` | Fixtures must be generated by or checked against the live path. |
| Open | Gate `>=3x` throughput claim on fresh benchmark artifacts. | `bd-x7nod`, `bd-21ds` | Artifact bundle records denominator, environment, commands, code revision, and observed value. |
| Open | Gate `>=10x` compromise reduction claim on fresh red-team artifacts. | `bd-x7nod` | Artifact bundle records baseline, FrankenEngine posture, scenario set, and success-rate calculation. |
| Open | Gate `<=250ms` containment latency claim on fresh runtime artifacts. | `bd-x7nod` | Artifact bundle records signal crossing, action timestamp, and median calculation. |
| Open | Gate `100%` deterministic replay coverage claim on fresh replay coverage artifacts. | `bd-x7nod` | Report covers all security-critical allow/deny/escalation decisions or downgrades wording. |
| Open | Add README CLI smoke for documented operator workflow. | `bd-3tsah`, related `bd-1ujhn` | Smoke runs `version`, `compile`, `verify compile-artifact`, `run`, and `replay` and links outputs. |
| Open | Re-run full compiler/lint/format/test gates after Rust code changes. | Future implementation beads | Required after substantive source edits, especially current dirty source/test surfaces. |

### Claim-To-Proof Matrix

| ID | Claim or promise | Source surface | Current evidence observed | Current status | Required next proof | Tracker |
|---|---|---|---|---|---|---|
| C01 | Native Rust execution without external JS engine bindings for core runtime behavior. | README TL;DR, PLAN Sections 2-4, AGENTS mission. | `baseline_interpreter.rs` has native `QuickJsLane`/`V8Lane` profiles sharing `InterpreterCore`; current focused cargo check passed. | `LIVE-CHECKED` for focused compile health; release-level claim still needs full gates. | Keep full all-targets/clippy/fmt/test gates green after source work; gate public wording through the matrix. | `bd-1qkrc` |
| C02 | Parser-to-IR-to-orchestrator execution is a real shipped path. | README CLI Contract and architecture docs. | `frankenctl compile`/`run` paths route through parser/lowering/orchestrator code, but the README workflow has no current smoke artifact in this pass. | `IMPLEMENTED-NOT-PROVEN` | Add a README CLI smoke that produces and verifies compile/run/replay artifacts. | `bd-3tsah` |
| C03 | Probabilistic guardplane with expected-loss actioning. | README capability table and PLAN strategy. | Runtime decision and guardplane modules exist, but no fresh live artifact was verified for the public claim in this pass. | `IMPLEMENTED-NOT-PROVEN` | Matrix row must link a live decision artifact with policy inputs, posterior/action, and verifier command. | `bd-1qkrc` |
| C04 | Deterministic replay and counterfactual policy simulation for high-severity/security-critical decisions. | README capability table, PLAN disruptive floor, charter evidence policy. | Counterfactual/replay code and CLI surfaces exist, but current `100%` replay coverage proof was not verified. | `BLOCKED-BY-PROOF-GAP` | Fresh replay coverage artifact must enumerate security-critical decision classes and prove coverage or downgrade `100%`. | `bd-x7nod` |
| C05 | Signed decision receipts, transparency-log proofs, and optional TEE attestation bindings. | README capability table. | Receipt/evidence modules and docs exist, but this pass did not verify transparency-log or TEE-backed artifact bundles. | `IMPLEMENTED-NOT-PROVEN` | Claim matrix must separate observed receipt signing from target/hypothesis transparency-log and TEE language. | `bd-1qkrc` |
| C06 | Fleet immune system with quarantine and revocation propagation plus bounded convergence SLOs. | README capability table, impossible-by-default index. | Quarantine propagation modules exist; at least one revocation example is fixture-heavy. | `STATIC-FIXTURE-RISK` | Live runtime/CLI proof must emit propagation decisions, timing/convergence evidence, and verifier output. | `bd-2wf47` |
| C07 | Capability-typed execution with ambient-authority rejection. | README capability table, PLAN impossible-by-default index. | Capability and authority modules/examples exist, but broad product claim needs artifact linkage across representative packages. | `IMPLEMENTED-NOT-PROVEN` | Matrix row must link live package compilation/execution artifacts proving ambient rejection on the shipped path. | `bd-1qkrc`, `bd-2wf47` |
| C08 | Deterministic information-flow confinement and signed declassification receipts. | PLAN impossible-by-default capability 12. | IFC/declassification source and example artifacts exist, but live source-to-sink proof was not verified in this pass. | `STATIC-FIXTURE-RISK` | Convert example proof to a live runtime path that generates receipts and validates provenance. | `bd-2wf47` |
| C09 | `>= 3x` weighted-geometric-mean throughput versus Node and Bun. | PLAN disruptive floor. | Benchmark specs/epics exist, but this pass did not verify a fresh denominator-matched artifact bundle. | `SPEC-OR-PLAN-ONLY` | Fresh benchmark gate must show denominator, environment, commands, revision, and observed metric. | `bd-x7nod`, `bd-21ds` |
| C10 | `>= 10x` reduction in successful red-team host compromise rate. | PLAN disruptive floor. | Security modules and prior tracker work exist, but no fresh red-team comparison artifact was verified here. | `SPEC-OR-PLAN-ONLY` | Fresh red-team artifact must compare baseline Node/Bun default posture to FrankenEngine under the declared scenario set. | `bd-x7nod` |
| C11 | `<= 250ms` median containment from high-risk signal crossing to action. | PLAN disruptive floor. | Containment/quarantine code exists, but no current latency artifact was verified. | `SPEC-OR-PLAN-ONLY` | Gate must consume event timestamps and compute median containment latency under declared workload conditions. | `bd-x7nod` |
| C12 | At least three production impossible-by-default features. | PLAN disruptive floor and Section 3.2. | Multiple candidate modules exist, but production status and artifact handles need per-feature proof. | `BLOCKED-BY-PROOF-GAP` | Matrix must identify exactly which three are production-observed and link proof artifacts; all others stay target/hypothesis. | `bd-1qkrc`, `bd-2wf47`, `bd-x7nod` |
| C13 | Evidence-first operations: every published performance/security claim ships with reproducible bundles. | README capability table, runtime charter. | The policy exists and relevant modules/docs exist, but enforcement over README/PLAN wording is missing. | `BLOCKED-BY-PROOF-GAP` | Add deterministic claim scanner/gate and fail closed on unsupported observed/superiority language. | `bd-1qkrc` |
| C14 | Shipped `frankenctl` surfaces are operator-ready where documented. | README CLI Contract and unsupported-surfaces language. | Source has real surfaces plus unsupported/fail-closed surfaces; README workflow still needs executable synchronization. | `IMPLEMENTED-NOT-PROVEN` | README smoke must prove documented surfaces and keep unsupported surfaces clearly separated. | `bd-3tsah`, `bd-1ujhn` |
| C15 | React/product-adjacent golden surfaces are ready enough to support runtime claims. | Current backlog and dirty worktree. | Current dirty files include React/golden/generated changes and open React golden beads exist. | `BLOCKED-BY-PROOF-GAP` | Do not use React/product-adjacent claims as proof until golden fixture blockers close and full gates rerun. | Existing React golden beads |

### Tracker Graph Created By This Pass

| Bead | Priority | Purpose | Dependencies |
|---|---:|---|---|
| `bd-1qkrc` | P1 | Gate README and PLAN claims on a live claim-to-proof matrix. | None. |
| `bd-2wf47` | P1 | Replace static security fixtures with live runtime proof paths. | None. |
| `bd-x7nod` | P1 | Gate disruptive floor metrics on fresh benchmark/security/replay artifacts. | Depends on `bd-1qkrc` and `bd-2wf47`. |
| `bd-3tsah` | P2 | Add README CLI workflow smoke with artifact linkage. | None. |

### Immediate Steering

Until the proof beads above close, the repository should treat the strongest
performance/security wording as `target` or `hypothesis`, not `observed`.
The native core is real enough to build on, and the focused compile check is
currently green, but category-defining language is still ahead of live,
repeatable proof.
