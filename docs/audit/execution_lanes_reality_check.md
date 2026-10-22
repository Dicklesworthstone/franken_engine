# FrankenEngine Reality Check — 2026-10-21

This assessment supersedes the historical lane assessment retained below.
Its consumer is the project owner requesting an end-to-end reality check; it
gates whether current implementation, release, and evidence claims can be
treated as delivered. It addresses observed stale architectural assertions,
failed claim validation, and a zero-step green smoke. Retire it when a later
revision-bound assessment supersedes its findings; artifact deletion still
requires the owner's authorization. This is an audit, not capability work.

## Verdict and evidence boundary

**FrankenEngine is a substantial working native runtime with a published CLI,
but it has not delivered the complete program in the canonical plan.**
The principal unfinished outcomes are trustworthy full ES2020 measurement,
semantic completion, general executable JIT/AOT tiers, the weighted Node/Bun
performance target, comparable security campaigns, live containment/fleet/TEE
measurements, and production/external qualification. More planning records
cannot substitute for those outcomes.

Source inspected: main `c9b999eae2da6ae7415f00f06dae44d4b2f34c1d`, with existing
uncommitted interpreter and integration-test edits preserved. Fresh executable
probes below use the **published v0.2.0 binary**, not a build of that main
revision. Source findings, release observations, historical receipts, and
unexecuted tests are separate evidence classes throughout this assessment.

Read completely: root `AGENTS.md`, all 2,548 lines of `README.md`, both files
under `docs/plans/` including the 2,606-line canonical plan, and the
reality-check skill and its planning/gap-analysis references. Additional intake
and source inspection covered the runtime charter, security model, claim
matrix, architecture, split contract, donor semantics, execution, evidence,
storage, Test262, native capsule, and fleet/latency producers. The documentation
inventory contains 506 Markdown files under `docs/`; this is not a claim that
every specialist document or every test target was individually revalidated.
The suite-wide `/data/projects/AGENTS.md` path is absent locally; local ancestor
guidance was read, and a reachable worker's copy was consulted. That copy lacks
the two named reward-hacking/work-graph sections referenced by root guidance;
their rules supplied in root guidance remain binding.

## Fresh results

Local artifact root:
`artifacts/reality_check/20261022T0027-JZjolY/`.

| Check | Result | What it establishes |
|---|---|---|
| Published release lookup | v0.2.0, published 2026-10-04; Linux x64, macOS arm64, Windows x64 assets and checksum sidecars | Distribution exists; no fresh installation/upgrade qualification |
| macOS arm64 archive | SHA256 `c6524725336ea0c14214589ba8f117cd837e4e0322250adf2b2c0bfe081a2744` matches GitHub's asset digest; binary reports 0.2.0 | Exact released executable used for the probes |
| Nine small JS programs, each compared with Node and Bun | All nine console outputs match | Arithmetic and numeric edge cases, array callbacks, descriptors, class inheritance, Promise order, typed-array coercion, RegExp lookbehind, exception/finally behavior on these inputs |
| Compile -> verify -> run -> strict replay, invoked directly | Pass | A real bounded release workflow; pure arithmetic replay reports `reexecution`, matching IR3/content/decisions, and zero nondeterminism events |
| Corrupt the actual `hashes.parse_event_ir` field | Verify exits 25 with a hash mismatch | The verifier rejects this concrete integrity mutation |
| Change a recorded console message | Strict replay exits 2 with unsigned execution-content divergence | Replay rejects this outcome mutation; it does not establish an external origin trust anchor |
| Four-backend arithmetic oracle | FrankenEngine/core/Node/Bun semantic consensus | Selected-cohort comparison works for one case; timing buckets are not a benchmark |
| `check` over a `fetch` call | Reports `NetworkEgress` requirement | Static footprint inference on this supported source, not an executed network effect or arbitrary-program noninterference |
| README CLI smoke wrapper, original | **False green:** exit 0, `steps=[]`, empty `events.jsonl`, `status=pass`, `failure_count=0` | BSD `date +%s%3N` breaks arithmetic before per-step evidence is recorded; repair and negative verification below |
| Claim-to-proof matrix gate, original | **Fail**, 3/28 rows | FE-CLAIM-006/008/009 source spans no longer contain required text; bindings repaired below |
| Claim freshness | **13/13 OBSERVED rows provisional** | Current environment/source/time recertification is missing; not a finding that all thirteen implementations fail |
| Theorem promotion gate | Pass, `STAY_HYPOTHESIS`, **0/6 qualifying bundles** | Honest refusal to promote FE-CLAIM-016 through 021, not six proved claims |
| Test262 posture consistency | Pass, three provisional vectors | Cross-file posture agrees; no full-corpus conformance result |
| Existing claim-gate portability regressions | 3 tests pass | Positive and adversarial validator behavior; synthetic validator inputs are not runtime proof |
| Fleet convergence `ci` gate | Pass | SLO schema and harness source references only; no measured fleet percentile |
| Containment-latency gate without supplied measurements | Exit 2: missing live input | No latency result was fabricated |
| Active dependency cycles | Empty | Active graph passes this structural check; historical closed cycles are separate |

The claim report is
`artifacts/claim_to_proof_matrix_gate/20261022T002641Z/claim_to_proof_gate_report.json`.
The theorem decision is
`artifacts/fe_claim_016_021_promotion/20261022T002641Z/promotion_decision.json`.
The nine-case results are retained in `probe-results.json` and
`extra-probe-results.json` under the local artifact root, with per-command
stdout/stderr and run reports. An initial mutation added an unused top-level
JSON field and was accepted; it did not modify a verified field and is not
counted as a failed integrity check. The subsequent actual-hash mutation above
is the negative integrity test.

`sbh check --need 20G` returned 1/critical, with about 190.9 GB available but
only 4.78% container headroom against its dynamic threshold. Per ancestor
instructions, no heavy Cargo lane was started. Thus **fresh main check, clippy,
fmt, full tests, and main-binary execution are unverified here**. Existing
retained compilation/test attempts include SIGTERM exit 143, queue refusal,
and unconfirmed completion; none is counted as a passing main gate. No disk
cleanup or peer-process intervention was performed.

## Maintenance follow-through after the audit

Under `bd-9vouw.511`, the existing README smoke now uses explicitly required
Python3 monotonic milliseconds, validates clock values before arithmetic,
rejects clock failure/regression, and refuses to publish success unless the
exact eight expected step records have matching exits, valid durations and
artifact hashes. Failure to enter the workspace also stops that command.
The runtime executable, semantic outputs and artifact validation rules were
preserved. The new Python regression target requires a real supplied binary;
it never builds or substitutes a passing engine.

Observed admit/reject split:

| Input | Original | Repaired |
|---|---|---|
| Real v0.2.0 CLI on macOS | Exit 0 with eight arithmetic errors and zero recorded steps | Exit 0, eight validated steps and numeric durations, no stderr; system and Homebrew Bash both exercised |
| Clock process failure / malformed value / regressing value | No valid clock-failure handling | Each exits nonzero without a passing bundle |
| Compile process exits 17 | Not counted as a baseline test | Failed step records exit 17 and wrapper exits nonzero |
| Event emitter silently loses every record | Original finalizer accepts an empty list | Finalizer rejects missing step evidence |
| Actual compile hash corruption | Release verifier rejects | Rejection retained under the regression suite |

Six regression tests passed twice; final pre-commit artifacts are in
`artifacts/readme_cli_workflow_smoke_tests/real-binary-q2iaigls/`.
Clock/command/event injection is harness validation only, not runtime security
evidence. Bash syntax and `shellcheck -x` passed. UBS found no critical issues;
strict JSON decoding in tests intentionally raises on malformed evidence.
Follow-through on 2026-10-22 re-executed the six regressions against committed
revision `c8242627dd784d0fe8e27c22adbeba767d512a70` on both macOS arm64
and Linux x64. Each platform completed two eight-step positive workflows and
all five injected failure cases. Separate artifact inspection verified all
seven file hashes, the directory-path hash and three bundle content hashes
per positive workflow; strict replay completed. The official Linux v0.2.0
archive matches published SHA256
`5be29592ad68fd33900300b7234b5c118075683a0aa08a94d8f6282fd3d41311`.
The five staged source/support files were checked against committed bytes.
Bash syntax, shellcheck and UBS passed; UBS reports zero critical findings
and seven strict JSON-decoding warnings in tests. Evidence is retained under
`artifacts/reality_check/20261022T0027-JZjolY/linux-readme/`, including the
Linux raw test artifacts and macOS command logs. This satisfies the harness
bug's acceptance by explicitly labeled **solo re-execution**; `bd-9vouw.511`
is closed. Independent verification and fresh-main Rust qualification are
still absent. No runtime, security or performance claim is promoted.

The three claim spans were rebound to the existing qualified README text:
006 -> line 144, 008 -> line 2408, 009 -> line 150. No required substring,
claim state, freshness window, receipt or verifier was weakened or re-dated.
The unchanged gate now exits 0 in `ci` with zero span failures and the same
13 provisional claims; `release` still exits 1 for those stale claims.
Artifacts are under `claims-rebound-ci/20261022T004642Z/` and
`claims-rebound-release/20261022T004642Z/` in the local artifact root. The JSON
report's span/wording verdict is `pass` in both modes; release rejection is the
subsequent process freshness verdict. Consumers must not mistake that JSON
field alone for release authorization.

One further documentation boundary remains under the existing docs-truth
owner: this smoke calls its SHA-256 links `link_signature` / `signed_link`,
but those are unkeyed content hashes, not Ed25519 manifest authentication.
Runtime-signed evidence inside a run report does not authenticate the outer
shell bundle. The maintenance fix does not promote that signature claim.

## Vision-to-implementation and work coverage

Status is scoped: a released bounded example can work while the complete
vision remains partial or unproved. Matrix wording state is not a substitute
for this implementation assessment.

| Goal | Current reality | Existing execution owners / remaining exit |
|---|---|---|
| Native ownership and useful JS execution | **Working bounded surface.** Real parser/lowering/interpreter, CLI, modules, builtins and security machinery; nine release probes pass. No binding-led JS engine was found in the inspected core path. | `bd-9vouw.5`, canonical BRIDGE-13/14/15/16/17; ordinary-package and regression qualification remain required |
| Complete ES2020 semantics | **Partial, current rate unknown.** Historical `120/47,157` is a defective runner-system measurement. The authoritative runner still uses value comparison; harness frontmatter is line-parsed, negatives are simplified, and suite cases default to HybridRouter. | `bd-performance-conformance-bridge-tu32j.13` and `.13.8`; HARNESS-ORACLE before a corrected full selected corpus, then semantic DAG to zero unwaived failures |
| Honest performance denominator and >=3x secure transactions vs both incumbents | **Target unproved.** June ratios are historical dirty/asymmetric/unweighted observations, not current speed or the normative denominator. | BRIDGE-02/19 and `bd-y6v8s`; both raw JS and equivalent secure-transaction scoreboards, frozen cases/weights, repeated same-host baselines, tails/RSS/equivalence |
| Fast interpreter and executable optimized tiers | **Real partial Tier I; general JIT/AOT not delivered.** `CompactTier1Program` compiles actual compact dispatch cells, preserves source binding, and falls back per unsupported instruction. The optional capsule module compiles/activates only a fixed non-JavaScript u64 probe. `aot_entrygraph_compiler` explicitly emits input-derived planning identities. | BRIDGE-01/03/04/05/06/07/08; shared semantics, full dispatch evidence, backend bakeoff, ABI/OSR/deopt/GC maps, actual bytes and exact fallback |
| Capability/IFC control and non-exfiltration | **Real selected-edge mechanisms; broad contract partial.** Typed capabilities, label propagation, declassification and authority inference exist. Engine/core flow-policy APIs differ; finite invariant tests are not arbitrary-program proofs. | `bd-7fhp3`, BRIDGE-09, `bd-fqlfw.8`, `bd-0y3b6`, `bd-vw7s1`; full effect/provenance coverage and adversarial source-to-sink tests before check elision |
| Authenticated chained evidence and deterministic replay | **Real implementation, current qualification incomplete.** Runtime/lab signing authorities, chain binding and replay are present; release reexecution and targeted corruption rejection work. Do not repeat old descriptions of the implementation as only public-seed signing or unchained entries. | `bd-90u6o`, `bd-8yhg4`, `bd-mpu1z` remain open/in progress for complete acceptance and independent recertification, not proof that their old code defects necessarily persist |
| >=10x host-compromise reduction and <=250ms containment | **Unproved targets.** Decision code and exact v2 comparison machinery are not a linked current campaign verdict or effective-containment measurement. A completed benign program can still be affected by stopping-policy behavior under the open `bd-pgzo7` acceptance. | `bd-0lim8`, `bd-pgzo7`, BRIDGE-09.10; ten-scenario real comparator campaign, stability/replay repetitions, false-positive countermetric and measured signal-to-effective-action |
| Fleet immunity, revocation, repair and convergence SLOs | **Primitives and bounded tests exist; deployment outcome unproved.** Contract-only `ci` success is not real topology/partition/transport evidence. | BRIDGE-23, its independent verification leaves under BRIDGE-21, `bd-cixqu.2.5`; real signed multi-process/multi-host fault campaign and measured percentiles |
| Hardware-backed receipts | **Simulated/fail-closed seam.** `tee_live_quote` does not produce real hardware quotes through the unwired SDK path. Fixed native-code probes are unrelated to TEE attestation. | BRIDGE-24 and independent hardware verification; real AMD/Intel quote, collateral, nonce/key/image binding and expiry/revocation negatives |
| Formal policy/compiler and proof-specialized speedup | **Hypothesis, not delivered end to end.** Z3/bounded validators, proof helpers and Lean sources are components; current promotion gate finds zero qualifying bundles. | `bd-cixqu.7.17`, BRIDGE-09/18/21; non-fixture product transforms, executable proof consumer, invalidation/rollback and equivalent-work performance evidence |
| Sibling reuse and downstream product | **Real source integrations, partial qualification.** Storage uses SQLModel/FrankenConnection seams and feature gates; source existence does not prove durability/recovery. Engine/product dependency direction is explicit. | `bd-cixqu.13.3`, `bd-15w28`, `bd-9vouw.3`, BRIDGE-21/25; exact default/all-feature/standalone consumers, persistence failure recovery, product handoff and release gates |
| React/FRX, Wasm and exposed compatibility features | **Bounded/partial; no full compatibility claim.** Compile/fallback and separate runtime surfaces exist. They were source-inspected rather than comprehensively executed in this session. | `bd-cixqu.16`, BRIDGE-25.8/.25.9, BRIDGE-26; preserve shipped features and qualify unsupported/fallback modes explicitly |
| PLAS, fleet privacy, reputation and autonomous operations | **Components and advisory behavior; production outcomes unproved here.** Shadow proposals are not applied production mutations; secure-aggregation types alone do not prove continuous privacy-preserving fleet learning. | `bd-11ua`, `bd-1rju` and its active children, `bd-twz2`, existing PLAS/shadow tracks; real cohorts, budget durability, false-deny/over-privilege metrics, burn-in and authorized adoption |
| Three production differentiators, GA and external validation | **Not established.** Demo directories include fixture-only checks; two observed features do not meet a three-feature floor. No current complete GA package or two independent reruns was established. | `bd-three-feature-floor-owner-2fjbh`, BRIDGE-19.5/.19.17, BRIDGE-25 and independent BRIDGE-21 leaves; exact released artifacts, clean installation/upgrade/recovery and genuine external results |

The native architecture decision requires care: its machine-readable file still
says `proposed` / `implementation_authorized=false`, **but `bd-9vouw.11` records
the owner's 2026-09-22 “Approve now” instruction**. The remaining issue is the
accepted-record/signature procedure, not an unasked architecture preference.
Do not solicit the same approval again or forge an owner signature. The
off-by-default fixed probe is not permission to claim general production JIT.

## Bridge, ambition and refinement disposition

The canonical Section 18 and existing BRIDGE graph already cover the major
vision goals. Creating another broad epic or rewriting the spec would add
process without closing a capability gap. The bridge is:

1. **Restore trustworthy observation first.** Fix the zero-step green smoke;
   repair actual source-span bindings, preserve freshness/drift checks, rerun
   eligible producers, and restore a complete exact-revision Rust gate run.
   Owners: `bd-9vouw.511`, `.10`, `.3`, `bd-15w28`, BRIDGE-00.2 and `bd-pa12f`.
2. **Finish G0 and canonical ownership.** HARNESS-ORACLE, exact ES2020 manifest,
   complete variant/terminal accounting, and corrected full Tier-R results run
   beside decomposed performance measurements. Resolve the 42 core-family
   ownership dispositions and monolith integration protocol. Owners: BRIDGE-01,
   02 and 12. No old percentage is promoted during this work.
3. **Deliver the useful vertical execution slices.** Carry shared semantics
   through real compact Tier I, then the authorized capsule and twelve-opcode
   native slice, then a representative extension package. Require exact
   effects, exceptions, budgets, labels, replay and fallback before expanding
   codegen. Owners: BRIDGE-03 through 09 and Section 18.14 S1/S2/S3.
4. **Close broad semantics and measured security in parallel where independent.**
   Execute semantic-cluster campaigns, benign/adversarial containment,
   comparable Node/Bun attacks, real fleet partitions and real TEE hardware.
   Hardware absence stays unavailable; schema-only success earns no deployment
   credit. Owners: BRIDGE-13 through 18, 23, 24, `bd-0lim8`, `bd-pgzo7`.
5. **Qualify the actual product and external outcomes.** Preserve the shipped
   feature inventory, all build modes, durable state and replay across faults;
   then assemble the immutable GA candidate, installer/upgrade/rollback proof
   and independent reruns. Owners: BRIDGE-19/21/25/26. Publication remains a
   separate explicitly authorized action.

Ambition passes retained the full original goals, sharpened the vertical
shared-semantics/native path, and included proof-derived security cost removal
plus real high-core/hardware work. They did not lower the >=3x, >=10x,
<=250ms, full-conformance or external-reproduction targets. Research levers
remain the existing falsifiable portfolio; no new speculative subsystem was
needed to explain the observed blockers.

Four refinement passes checked goal coverage, dependency/ownership boundaries,
positive/negative verification, and release/operator failure semantics. They
corrected three tempting misclassifications: old conformance percentages as
current semantics, a fixed native probe as a general JIT, and the green smoke
as eight validated steps. The final review found no further distinct backlog
gap among the audited goals. This is a scoped coverage conclusion, not a proof
that every conceivable behavior is tracked.

**Would completing all existing beads finish the vision?** On paper, the broad
BRIDGE graph includes semantic, performance, security, production and external
exits. Actually satisfying those acceptance criteria would close the audited
gaps. Closing implementation/scaffold beads alone would not: hardware results,
independent reproduction, adoption and released-consumer evidence are outcomes
that cannot be obtained by marking tasks complete. The newly demonstrated
macOS zero-step green lacked an exact existing owner, so `bd-9vouw.511` was
created. Findings were appended to the existing docs-truth and BRIDGE-00.2
owners rather than duplicating the program.

Initial authoritative JSONL census: 5,090 unique issues — 3,933 closed,
669 open, 433 in progress, 45 blocked and 10 deferred. These counts are not a
capability-completion percentage. `bv --robot-triage` returned recommendations,
including canonical ownership and measurement prerequisites; its displayed
census differs from the direct JSONL census, so no merged completion statistic
is inferred. The root SQLite cache is schema 17 while installed `br` expects
19. Tracker edits use a fresh isolated cache imported from all 5,090 JSONL
records, with exact semantic-diff and freshness checks before publication;
the shared cache and unrelated edits are preserved.

The initial audit changed no Rust runtime source, runtime acceptance threshold,
claim state or release. Maintenance changed the smoke runner, added its
real-binary regression target, and corrected three claim source bindings. No
issues were closed during that initial audit. The filled session honesty/work
worksheets are retained at
`artifacts/reality_check/20261022T0027-JZjolY/session-honesty-disposition.md`.
Disposition: the observed zero-step green was repaired and disclosed;
gate self-weakening and proof-class inflation were checked explicitly. The
audit earns no runtime/performance capability credit. All verification here
is solo re-execution, not independent review. Full main compilation/testing,
Windows release execution, exhaustive package/React/Wasm compatibility,
live fleet/TEE campaigns, complete conformance and external reproduction
remain explicitly unverified.

The subsequent stream implementation under `bd-305gi.2` remains partial:
mixed CJS routes share the existing module loader, and writable completion
now preserves callback-scheduled nextTick order. Nine production-JavaScript
tests pass beside live Node20/24/26; the previous source fails five of those
nine. These are host tests, not native lowering proof. The four added Rust
regressions and native capability/IFC/replay qualification remain unexecuted,
and full CJS facade retirement remains open. Local disk admission still
refuses heavy Cargo lanes. The released engine rejects the first-class
EventEmitter import required to host the current factory as guest source;
that attempted shortcut provides no current-main integration credit. No
cache was deleted, gate weakened or peer process interrupted.

## Historical assessment — superseded, retained for provenance

The following earlier assessment used old lane terminology and asserted full
completion from routing/configuration. Its “fully implemented” and “no work
needed” conclusions must not be used as present program or performance proof.

# Execution Lanes vs Plan Section 8.2 Reality Check

## Summary

The plan's Section 8.2 specifies a three-lane execution architecture. The current implementation **fully implements** this architecture but with slightly different naming conventions, creating a false appearance of missing implementation.

## Plan Requirements (Section 8.2 Engine Lanes)

**Required Components**:
- `quickjs_inspired_native`: deterministic and low-overhead execution lane  
- `v8_inspired_native`: throughput/compatibility-oriented lane
- `hybrid_router`: policy-directed selection with deterministic fallback

## Current Implementation Analysis

### ✅ Three-Lane Architecture EXISTS
**Source**: `crates/franken-engine/src/lib.rs`

**1. QuickJs Inspired Native Lane**:
```rust
#[derive(Debug, Default)]
pub struct QuickJsInspiredNativeEngine;

impl JsEngine for QuickJsInspiredNativeEngine {
    fn kind(&self) -> EngineKind {
        EngineKind::QuickJsInspiredNative
    }
    
    fn eval_prepared(&mut self, prepared: PreparedEvalSource, route_reason: RouteReason) -> EvalResult<EvalOutcome> {
        eval_with_lane(prepared, LaneChoice::QuickJs, route_reason)
    }
}
```

**2. V8 Inspired Native Lane**:
```rust
#[derive(Debug, Default)]
pub struct V8InspiredNativeEngine;

impl V8InspiredNativeEngine {
    fn eval_prepared(&mut self, prepared: PreparedEvalSource, route_reason: RouteReason) -> EvalResult<EvalOutcome> {
        eval_with_lane(prepared, LaneChoice::V8, route_reason)
    }
}
```

**3. Hybrid Router with Policy-Directed Selection**:
```rust
#[derive(Debug)]
pub struct HybridRouter {
    quickjs_lineage: QuickJsInspiredNativeEngine,
    v8_lineage: V8InspiredNativeEngine,
}

impl HybridRouter {
    pub fn classify_source_route(source: &str) -> RouteReason {
        route_reason_for_source(source)  // Policy-directed classification
    }
    
    pub fn eval(&mut self, source: &str) -> EvalResult<EvalOutcome> {
        let route_reason = Self::classify_source_route(source);
        match route_reason {
            RouteReason::ContainsImportKeyword | RouteReason::ContainsAwaitKeyword => {
                // Routes to V8 lane for complex features
                self.v8_lineage.eval_prepared(prepared, route_reason)
            }
            _ => {
                // Routes to QuickJs lane for deterministic execution  
                self.quickjs_lineage.eval_prepared(prepared, RouteReason::DefaultQuickJsPath)
            }
        }
    }
}
```

### ✅ Policy-Directed Selection Logic
**Source**: Route classification in `HybridRouter::classify_source_route()`

Current routing policies:
- **Import/Module syntax** → V8 lane (complexity handling)
- **Await/Async syntax** → V8 lane (async runtime)
- **Default/Simple JS** → QuickJs lane (deterministic, low-overhead)

### ✅ Connection to Baseline Execution
**Source**: `crates/franken-core/src/baseline_interpreter.rs`

The lanes connect to actual execution via:
```rust
eval_with_lane(prepared, LaneChoice::QuickJs, route_reason)  // → QuickJsLane::execute()
eval_with_lane(prepared, LaneChoice::V8, route_reason)       // → V8Lane::execute()  
```

Both lanes use native `InterpreterCore` with different configurations (confirmed in previous analysis).

### ✅ Test Coverage
**Source**: Comprehensive test suite in `lib.rs`

Tests verify:
- `hybrid_routes_simple_input_to_quickjs()` 
- `hybrid_routes_import_to_v8()`
- Individual lane behavior
- Error handling consistency across lanes

## The "Missing Implementation" Misconception

### Naming Convention Differences
| Plan Specification | Implementation Name |
|-------------------|---------------------|
| `quickjs_inspired_native` | `QuickJsInspiredNativeEngine` |
| `v8_inspired_native` | `V8InspiredNativeEngine` |
| `hybrid_router` | `HybridRouter` |

### Why the Gap Appeared
1. **Snake_case vs PascalCase**: Plan uses snake_case, code uses PascalCase structs
2. **Search Strategy**: Looking for exact string matches (`quickjs_inspired_native`) misses actual implementations
3. **Scattered References**: Scheduling/test code references create noise when searching

## Verification of Completeness

### ✅ Architecture Requirements Met
- **Deterministic lane**: QuickJsInspiredNativeEngine provides low-overhead execution
- **Throughput lane**: V8InspiredNativeEngine handles complex features  
- **Policy selection**: HybridRouter routes based on source analysis
- **Deterministic fallback**: Default to QuickJs lane for simple cases

### ✅ Integration Requirements Met  
- **Lane execution**: Both connect to native InterpreterCore via LaneRouter
- **Route reasons**: Rich routing metadata (RouteReason enum) for debugging
- **Error consistency**: Identical error handling across lanes
- **Engine identification**: EngineKind tracks which lane executed code

## Resolution

**No implementation work needed**. The Section 8.2 three-lane architecture is **fully implemented and operational**.

**Recommended Actions**:
1. **Documentation Update**: Add alias/search terms mapping plan names to implementation names
2. **Naming Alignment**: Consider adding type aliases for exact plan naming:
   ```rust
   pub type quickjs_inspired_native = QuickJsInspiredNativeEngine;
   pub type v8_inspired_native = V8InspiredNativeEngine;  
   pub type hybrid_router = HybridRouter;
   ```
3. **Discoverability**: Add comments with plan section references to main engine structs

**Gap Assessment**: **FALSE POSITIVE** - Architecture exists with full functionality, only naming conventions differ from plan specification.
