# FrankenEngine

<div align="center">
  <img src="docs/assets/franken_engine_illustration.webp" alt="FrankenEngine - Native Rust runtime for high-trust extension workloads">
</div>

<div align="center">

[![Rust 2024](https://img.shields.io/badge/Rust-2024-orange.svg)](https://www.rust-lang.org/)
[![Unsafe Forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://doc.rust-lang.org/reference/unsafe-keyword.html)
[![Deterministic Replay](https://img.shields.io/badge/replay-deterministic-blue.svg)](./PLAN_TO_CREATE_FRANKEN_ENGINE.md)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

</div>

Native Rust runtime for adversarial extension workloads, with deterministic replay surfaces, signed evidence contracts, and explicit proof-state tracking for cryptographic decision receipts and fleet-scale containment.

<div align="center">
<h3>Quick Start From Source</h3>

```bash
git clone https://github.com/Dicklesworthstone/franken_engine.git
cd franken_engine
cargo build --release -p frankenengine-engine --bin frankenctl
./target/release/frankenctl version
```

<p><em>This repository currently ships Rust workspace crates and source-built utility binaries, not a packaged installer or prebuilt release binaries.</em></p>
</div>

---

## TL;DR

### The Problem
Node and Bun are fast enough for many workloads, but extension-heavy agent systems need a different default posture: active containment, deterministic forensics, and explicit runtime authority boundaries.

### The Solution
FrankenEngine provides one native baseline interpreter with deterministic and throughput execution profiles, a probabilistic guardplane with expected-loss actioning, targeted deterministic replay for high-severity decisions, and signed evidence contracts for every high-impact containment event.

### Why Use FrankenEngine?

| Capability | What You Get In Practice |
|---|---|
| Native execution profiles | 🟢 OBSERVED (live proof linked) `baseline_deterministic_profile` for conservative control paths, `baseline_throughput_profile` for throughput-heavy paths, and `adaptive_profile_router` when policy routing is enabled |
| Probabilistic Guardplane | 🟢 OBSERVED (live proof linked) Bayesian risk updates and e-process boundaries that trigger `allow/challenge/sandbox/suspend/terminate/quarantine` |
| Deterministic replay | 🟡 TARGETED (gate exists but baseline placeholder) Bit-stable replay for high-severity decision paths with counterfactual policy simulation |
| Cryptographic governance | 🔴 HYPOTHESIS (claim not yet provable) Signed decision receipts with transparency-log proofs and optional TEE attestation bindings |
| Fleet immune system | 🟡 TARGETED (provisional example only) Quarantine and revocation propagation require live runtime/CLI proof before bounded convergence SLOs are treated as observed |
| Capability-typed execution | 🔴 HYPOTHESIS (end-to-end contract not shipped) Compile-time capability-typed TS-to-IR and ambient-authority rejection are not shipped; current code provides selected runtime capability gates |
| Cross-repo constitution | 🟢 OBSERVED (live proof linked) Control plane on `/dp/asupersync`, TUI on `/dp/frankentui`, SQLite on `/dp/frankensqlite` |
| Evidence-first operations | 🟡 TARGETED (gate exists but baseline placeholder) Every published performance and security claim ships with reproducible artifact bundles |

## CLI Contract

The shipped `frankenctl` CLI provides core execution surfaces and selective 
operator tooling. **Shipped surfaces**: `version`, `compile`, `run`, `doctor`, 
`verify`, `benchmark`, `replay`, `react`, `gates`, `reports`, `test`, `synth`, 
`orchestrate`, and `runtime`. See [Unsupported Surfaces](#unsupported-surfaces) 
for production guidance.

The `frankenctl` examples below document the first-run operator contract from a source checkout:

```bash
# 1) Build the source CLI binary used below
cargo build --release -p frankenengine-engine --bin frankenctl

# 2) Verify the CLI binary and schema version  
./target/release/frankenctl version

# 3) Create a tiny source file and artifact directory
mkdir -p ./artifacts
printf 'const answer = 40 + 2;\n' > ./demo.js

# 4) Compile source to a versioned artifact
./target/release/frankenctl compile --input ./demo.js --out ./artifacts/demo.compile.json --goal script

# 5) Verify the compile artifact contract
./target/release/frankenctl verify compile-artifact --input ./artifacts/demo.compile.json

# 6) Execute the same source through the orchestrator  
./target/release/frankenctl run --input ./demo.js --extension-id demo-ext --out ./artifacts/demo.run.json

# 7) Replay a captured nondeterminism trace (requires the checked-in sample trace)
#    Note: steps 1-6 emit compile/run reports, not replay traces
./target/release/frankenctl replay run --trace ./examples/05_replay_demo/sample_trace.json --mode strict --out ./artifacts/replay_report.json
```

The README CLI contract is covered by a user-facing smoke workflow:

```bash
FRANKENCTL_BIN=./target/release/frankenctl ./scripts/e2e/readme_cli_workflow_smoke.sh
```

Each run writes a signed artifact manifest, structured events, command
transcript, stdout/stderr captures, and the emitted compile/run/replay artifacts
under `artifacts/readme_cli_workflow_smoke/<timestamp>/`.

## Design Philosophy

1. **Runtime ownership over wrappers**
FrankenEngine owns parser-to-scheduler semantics in Rust. Compatibility is a product layer in `franken_node`, not a hidden wrapper around third-party engines.

2. **Security and performance as co-equal constraints**
The project does not trade correctness for speed or speed for policy theater. Optimizations ship with behavior proofs and rollback artifacts.

3. **Deterministic first, adaptive second**
Live decisions must replay deterministically from fixed artifacts. Adaptive learning is allowed, but only through signed promoted snapshots.

4. **Evidence before claims**
Benchmarks, containment metrics, and policy assertions are tied to reproducible artifacts. No artifact, no claim.

5. **Constitutional integration**
FrankenEngine reuses stronger sibling substrates instead of rebuilding them: asupersync control contracts, frankentui operator surfaces, and frankensqlite persistence.

## Runtime Charter

Runtime governance and native-only execution boundaries are defined in [`docs/RUNTIME_CHARTER.md`](./docs/RUNTIME_CHARTER.md).

The live claim-language ledger is [`docs/CLAIM_TO_PROOF_MATRIX_V1.md`](./docs/CLAIM_TO_PROOF_MATRIX_V1.md), backed by [`docs/claim_to_proof_matrix_v1.json`](./docs/claim_to_proof_matrix_v1.json) and checked with `./scripts/run_claim_to_proof_matrix_gate.sh ci`.

Donor-harvesting governance boundaries (semantic extraction allowlist + architectural denylist) are defined in [`docs/DONOR_EXTRACTION_SCOPE.md`](./docs/DONOR_EXTRACTION_SCOPE.md).

Semantic compatibility source-of-truth entries for donor-observable behavior are defined in [`docs/SEMANTIC_DONOR_SPEC.md`](./docs/SEMANTIC_DONOR_SPEC.md).

Native architecture synthesis derived from that semantic contract is defined in [`docs/architecture/frankenengine_native_synthesis.md`](./docs/architecture/frankenengine_native_synthesis.md).

This charter is the acceptance gate for architecture changes and codifies:
- native Rust ownership of core execution semantics
- prohibition of binding-led core execution backends
- deterministic replay + evidence-linkage obligations for high-impact actions
- binding claim-language policy tied to reproducible artifact state
- repository split and sibling-reuse constraints

Reproducibility bundle templates (`env.json`, `manifest.json`, `repro.lock`) are defined in [`docs/REPRODUCIBILITY_CONTRACT.md`](./docs/REPRODUCIBILITY_CONTRACT.md) and shipped under [`docs/templates/`](./docs/templates/).

## Comparison

| Dimension | FrankenEngine | Node.js | Bun |
|---|---|---|---|
| Core execution ownership | Native Rust baseline interpreter + profile router | V8 embedding | JavaScriptCore + Zig runtime |
| Deterministic replay for high-severity decisions | Targeted gate with shipped replay APIs; end-to-end byte-identical proof is not yet observed | External tooling only | External tooling only |
| Probabilistic containment policy | Built in guardplane | Not default runtime behavior | Not default runtime behavior |
| Cryptographic decision receipts | HYPOTHESIS until transparency-log and optional TEE proof artifacts promote the claim | Not a core runtime primitive | Not a core runtime primitive |
| Fleet quarantine convergence model | TARGETED/provisional SLO and fault-injection gates; live bounded convergence is not yet an observed production claim. **Note**: De-escalation unimplemented - containment operates as permanent ratchet | App-specific integration | App-specific integration |
| Capability-typed extension contract | Selected runtime capability gates; compile-time TS-to-IR contract not shipped | Not native to runtime | Not native to runtime |
| Cross-runtime lockstep oracle | Built in Node/Bun differential harness | N/A | N/A |

## Build Modes

FrankenEngine supports two build modes to accommodate different development and deployment environments:

## RGC Execution Profile Contract

Execution-profile policy is pinned by `docs/RGC_EXECUTION_PROFILE_CONTRACT_MIGRATION_V1.md`.

```toml
[execution_profiles]
baseline_deterministic_profile_enabled = true
baseline_throughput_profile_enabled = true
fallback_lane = "baseline_deterministic_profile"
```

The supported runtime profile identifiers are `baseline_deterministic_profile`, `baseline_throughput_profile`, and `adaptive_profile_router`.

### Standalone Mode
For developers working without the full asupersync repository layout:

```bash
# Build without external dependencies
cargo check --no-default-features
cargo build --no-default-features --release

# Test standalone functionality
cargo test --no-default-features
```

In standalone mode:
- Core interpreter functionality available
- Governance modules compile with fallback behavior
- External policy integration disabled
- Suitable for development and testing

### Full Integration Mode
For integration builds with the complete asupersync ecosystem:

```bash
# Build with all external dependencies
cargo check --all-features
cargo build --all-features --release

# Test full integration
cargo test --all-features
```

In full integration mode:
- Governance and policy enforcement integration surfaces compile and run behind their current proof gates
- Cross-repository coordination surfaces are enabled where sibling repositories are present
- TEE attestation bindings and bounded fleet quarantine remain HYPOTHESIS/TARGETED security claims until promoted by live proof artifacts
- Cryptographic decision receipts compile their integration seams and validation gates, but transparency-log and TEE-backed production guarantees remain governed by the claim-to-proof matrix

### Verifying Build Modes

Use the provided verification script to test both modes:

```bash
./scripts/verify_build_modes.sh
```

See [`docs/DEPENDENCY_AUDIT.md`](./docs/DEPENDENCY_AUDIT.md) for detailed dependency information.

## Cross-Repo Integration Suite

The cross-repo integration suite verifies FrankenEngine sibling boundaries with `/dp/asupersync`, `/dp/frankentui`, `/dp/frankensqlite`, and the service/control contracts around them. The suite is the operator entry point for checking that schema contracts, structured logs, degraded-mode diagnostics, and replay artifacts remain aligned across those repositories.

```bash
./scripts/run_cross_repo_integration_suite.sh ci
./scripts/e2e/cross_repo_integration_suite_replay.sh
```

The machine-readable contract is [`docs/cross_repo_integration_suite_v1.json`](./docs/cross_repo_integration_suite_v1.json), and the operator guide is [`docs/CROSS_REPO_INTEGRATION_SUITE.md`](./docs/CROSS_REPO_INTEGRATION_SUITE.md).

## RGC FrankenNode Handoff Bundle Gate

`bd-1lsy.5.10.3` packages the engine-owned support-surface contract and blocker ledger into a deterministic handoff bundle for `/dp/franken_node`, with sibling smoke checks and fail-closed routing when upstream evidence is missing, stale, or orphaned.

```bash
# franken_node handoff bundle gate (rch-backed check + test + clippy + sibling smoke checks)
RGC_HANDOFF_BLOCKER_LEDGER_PATH=/abs/path/engine_product_blocker_ledger.json \
  ./scripts/run_rgc_franken_node_handoff_bundle.sh ci

# deterministic replay wrapper
RGC_HANDOFF_BLOCKER_LEDGER_PATH=/abs/path/engine_product_blocker_ledger.json \
  ./scripts/e2e/rgc_franken_node_handoff_bundle_replay.sh ci

# exact preserved-run replay without rerunning the lane
RGC_FRANKEN_NODE_HANDOFF_BUNDLE_REPLAY_RUN_DIR=artifacts/rgc_franken_node_handoff_bundle/<timestamp> \
  ./scripts/e2e/rgc_franken_node_handoff_bundle_replay.sh ci
```

The replay wrapper resolves the latest complete handoff bundle, warns when it must skip a newer incomplete run directory, and fails closed if no complete bundle exists. When `RGC_FRANKEN_NODE_HANDOFF_BUNDLE_REPLAY_RUN_DIR` is set, the wrapper replays that exact preserved bundle instead of rerunning the lane; the directory must already contain the full artifact set or replay fails closed.

Artifacts are written under:

- `artifacts/rgc_franken_node_handoff_bundle/<timestamp>/run_manifest.json`
- `artifacts/rgc_franken_node_handoff_bundle/<timestamp>/events.jsonl`
- `artifacts/rgc_franken_node_handoff_bundle/<timestamp>/commands.txt`
- `artifacts/rgc_franken_node_handoff_bundle/<timestamp>/trace_ids.json`
- `artifacts/rgc_franken_node_handoff_bundle/<timestamp>/franken_node_handoff_manifest.json`
- `artifacts/rgc_franken_node_handoff_bundle/<timestamp>/sibling_smoke_verification.json`
- `artifacts/rgc_franken_node_handoff_bundle/<timestamp>/support_surface_summary.md`
- `artifacts/rgc_franken_node_handoff_bundle/<timestamp>/franken_node_handoff_bundle_contract.json`
- `artifacts/rgc_franken_node_handoff_bundle/<timestamp>/engine_product_blocker_ledger.json`
- `artifacts/rgc_franken_node_handoff_bundle/<timestamp>/step_logs/step_000.log`

## RGC Certified Optimization Harness

The certified optimization harness validates rewrite/e-graph optimization
evidence and refuses local RCH fallback for heavy commands. Run or replay it
with:

```bash
./scripts/run_rgc_certified_optimization_harness.sh ci
./scripts/e2e/rgc_certified_optimization_harness_replay.sh ci
```

`check` mode emits only the control-plane bundle: `run_manifest.json`,
`events.jsonl`, `commands.txt`, `trace_ids.json`, and `rch-log.*` files.
`test` and `ci` additionally emit `rewrite_proof_index.json` and
`egraph_rewrite_pack.json`; the replay wrapper reports the latest first rch log
when diagnosing incomplete or failed preserved bundles.

## RGC Exception and Diagnostic Semantics Gate

The exception and diagnostic semantics gate freezes cross-layer error metadata,
differential conformance rules, and replayable diagnostic traces. Run and replay
the gate with:

```bash
./scripts/run_rgc_exception_diagnostics_semantics.sh ci
./scripts/e2e/rgc_exception_diagnostics_semantics_replay.sh ci
```

The gate is specified by `docs/rgc_exception_diagnostics_semantics_v1.json` and
`docs/rgc_exception_diagnostics_semantics_vectors_v1.json`. Complete bundles
write `artifacts/rgc_exception_diagnostics_semantics/<timestamp>/run_manifest.json`,
`artifacts/rgc_exception_diagnostics_semantics/<timestamp>/events.jsonl`,
`artifacts/rgc_exception_diagnostics_semantics/<timestamp>/commands.txt`, and
`artifacts/rgc_exception_diagnostics_semantics/<timestamp>/diagnostic_trace.json`.

## RGC Fault-Injection and Chaos Verification Pack

The fault-injection and chaos verification pack keeps deterministic chaos
vectors, fail-closed artifact validation, and replay evidence in one gate. Run
and replay it with:

```bash
./scripts/run_rgc_fault_injection_chaos_verification_pack.sh ci
./scripts/e2e/rgc_fault_injection_chaos_verification_pack_replay.sh ci
```

The pack is specified by
`docs/rgc_fault_injection_chaos_verification_pack_v1.json` and
`docs/rgc_fault_injection_chaos_verification_vectors_v1.json`. Complete bundles
write
`artifacts/rgc_fault_injection_chaos_verification_pack/<timestamp>/run_manifest.json`,
`artifacts/rgc_fault_injection_chaos_verification_pack/<timestamp>/events.jsonl`,
`artifacts/rgc_fault_injection_chaos_verification_pack/<timestamp>/commands.txt`,
`artifacts/rgc_fault_injection_chaos_verification_pack/<timestamp>/chaos_verification_report.json`,
and `artifacts/rgc_fault_injection_chaos_verification_pack/<timestamp>/step_logs/step_*.log`.

## RGC Performance Regression Gate

The performance regression gate ranks culprit deltas, applies statistical
significance and waiver policy, and emits replayable evidence for optimization
changes. Run and replay it with:

```bash
./scripts/run_rgc_performance_regression_gate.sh ci
./scripts/e2e/rgc_performance_regression_gate_replay.sh ci
```

The gate is specified by `docs/rgc_performance_regression_gate_v1.json`.
Complete runs write `run_manifest.json`, `events.jsonl`, `commands.txt`, and
`regression_report.json` under
`artifacts/rgc_performance_regression_gate/<timestamp>/`.

## RGC Statistical Validation Pipeline

The statistical validation pipeline checks significance thresholds and
performance-verdict support artifacts for regression claims. Run and replay it
with:

```bash
./scripts/run_rgc_statistical_validation_pipeline.sh ci
./scripts/e2e/rgc_statistical_validation_pipeline_replay.sh ci
```

The pipeline is specified by `docs/rgc_statistical_validation_pipeline_v1.json`.
Complete bundles include
`artifacts/rgc_statistical_validation_pipeline/<timestamp>/run_manifest.json`
with `events.jsonl`, `commands.txt`, and
`support_bundle/stats_verdict_report.json` evidence.

## RGC Performance and Regression Verification Pack

The performance and regression verification pack verifies the broader
operator-facing regression workflow around performance evidence, gate replay,
and incident handoff. Run and replay it with:

```bash
./scripts/run_rgc_performance_regression_verification_pack.sh ci
./scripts/e2e/rgc_performance_regression_verification_pack_replay.sh ci
```

The pack is specified by `docs/rgc_performance_regression_verification_pack_v1.json`.
Complete bundles include
`artifacts/rgc_performance_regression_verification_pack/<timestamp>/run_manifest.json`
alongside the run `events.jsonl` and `commands.txt` evidence.

## RGC Runtime Semantics Verification Pack

The runtime semantics verification pack checks deterministic semantics vectors
for runtime behavior, report generation, and replay. Run and replay it with:

```bash
./scripts/run_rgc_runtime_semantics_verification_pack.sh ci
./scripts/e2e/rgc_runtime_semantics_verification_pack_replay.sh ci
```

The pack is specified by `docs/rgc_runtime_semantics_verification_pack_v1.json`
and `docs/rgc_runtime_semantics_verification_vectors_v1.json`. Complete bundles
write `artifacts/rgc_runtime_semantics_verification_pack/<timestamp>/run_manifest.json`,
`artifacts/rgc_runtime_semantics_verification_pack/<timestamp>/events.jsonl`,
`artifacts/rgc_runtime_semantics_verification_pack/<timestamp>/commands.txt`,
`artifacts/rgc_runtime_semantics_verification_pack/<timestamp>/runtime_semantics_verification_report.json`,
and `artifacts/rgc_runtime_semantics_verification_pack/<timestamp>/step_logs/step_*.log`.

## RGC Security Enforcement Verification Pack

The security enforcement verification pack checks attack-class vectors,
fail-closed policy behavior, and replay completeness for enforcement evidence.
Run and replay it with:

```bash
./scripts/run_rgc_security_enforcement_verification_pack.sh ci
./scripts/e2e/rgc_security_enforcement_verification_pack_replay.sh ci
RGC_SECURITY_ENFORCEMENT_VERIFICATION_PACK_REPLAY_RUN_DIR=artifacts/rgc_security_enforcement_verification_pack/<timestamp> \
  ./scripts/e2e/rgc_security_enforcement_verification_pack_replay.sh ci
```

The pack is specified by `docs/rgc_security_enforcement_verification_pack_v1.json`
and `docs/rgc_security_enforcement_verification_vectors_v1.json`; its test
surface is `crates/franken-engine/tests/rgc_security_enforcement_verification_pack.rs`.
Complete bundles write
`artifacts/rgc_security_enforcement_verification_pack/<timestamp>/step_logs/step_*.log`,
`artifacts/rgc_security_enforcement_verification_pack/<timestamp>/trace_ids.json`,
and `artifacts/rgc_security_enforcement_verification_pack/<timestamp>/security_verification_report.json`.

## Parser Phase0 Artifact Contract

The parser phase0 performance artifact contract defines truthful performance evidence requirements and degraded-mode receipt handling. This contract ensures placeholder artifacts are rejected and real capture failures are explicitly documented.

To verify the artifact contract:

```bash
./scripts/run_parser_phase0_artifact_contract.sh ci
./scripts/e2e/parser_phase0_artifact_contract_replay.sh ci
```

See [`docs/PARSER_PHASE0_ARTIFACT_CONTRACT_V1.md`](./docs/PARSER_PHASE0_ARTIFACT_CONTRACT_V1.md) for the complete contract specification.

## Parser Performance Promotion Gate

The parser performance promotion gate verifies declared Boa/peer wins on fixed
workloads and quantiles with reproducible artifact bundles. Run the gate through
the repo-local RCH target namespace so remote builds do not depend on fragile
temporary directories:

```bash
CARGO_TARGET_DIR=$PWD/target_rch_parser_performance_promotion_gate_verify \
  ./scripts/run_parser_performance_promotion_gate.sh ci
./scripts/e2e/parser_performance_promotion_gate_replay.sh
```

Gate runs emit `run_manifest.json`, `events.jsonl`, `commands.txt`, and
`step_logs/step_*.log` under `artifacts/parser_performance_promotion_gate/<timestamp>/`.
The replay wrapper prints the latest complete artifact bundle and will skip a
newer incomplete run directory with a warning. If an operator interrupts a
remote step, the manifest stays anchored to the in-flight command instead of
leaving step-log-only output; normal runs still surface `step_000.log` in the
operator verification commands.

See [`docs/PARSER_PERFORMANCE_PROMOTION_GATE.md`](./docs/PARSER_PERFORMANCE_PROMOTION_GATE.md) for the full gate contract.

## Parser Frontier Harness

The parser frontier harness composes the optional chaining, tagged-meta frontier,
and parser-gap inventory lanes into one replayable evidence bundle. Run the full
CI scenario with:

```bash
./scripts/run_parser_frontier_harness.sh ci
./scripts/e2e/parser_frontier_harness_replay.sh full ci
```

Each run writes a bundle under `artifacts/parser_frontier_harness/<timestamp>/`
with `run_manifest.json`, `events.jsonl`, `commands.txt`, `trace_ids.json`,
`parser_gap_report.json`, and the `case_diagnostics` artifact directory
recorded as `case_diagnostics_dir` in the contract fixture.

## Parser Oracle Missing-Artifact Contract

The parser oracle missing-artifact contract records explicit receipt states for
known absent artifacts and rejects anonymous backfills. Run and replay the
contract with:

```bash
./scripts/run_parser_oracle_missing_artifact_contract.sh ci
./scripts/e2e/parser_oracle_missing_artifact_contract_replay.sh ci
```

Complete runs write `run_manifest.json`, `trace_ids.json`, `events.jsonl`,
`commands.txt`, `step_logs/step_000.log`,
`parser_oracle_missing_artifact_contract.json`, and
`parser_oracle_missing_artifact_contract_validation_report.json` under
`artifacts/parser_oracle_missing_artifact_contract/<timestamp>/`.

## Lowering Gap Truth Invariant

The lowering gap truth invariant defines the authoritative relationship between lowering status fields and execution-readiness flags. This contract ensures that `status`, `parser_ready_syntax`, `execution_ready_semantics`, and prose fields cannot report mutually incompatible states in the lowering gap inventory.

To verify the invariant contract:

```bash
./scripts/run_lowering_gap_truth_invariant.sh ci
./scripts/e2e/lowering_gap_truth_invariant_replay.sh ci
```

See [`docs/LOWERING_GAP_TRUTH_INVARIANT_V1.md`](./docs/LOWERING_GAP_TRUTH_INVARIANT_V1.md) for the complete invariant specification.

## RGC Compound JSON Runtime Proof Lanes

Compound `JSON.parse` / `JSON.stringify` semantics are defined in
[`docs/RGC_COMPOUND_JSON_RUNTIME_CONTRACT_V1.md`](./docs/RGC_COMPOUND_JSON_RUNTIME_CONTRACT_V1.md).
The proof lanes show that the runtime traverses heap-backed compound values and
that the old placeholder strings remain closed in the zero-placeholder
inventory.

Run and replay the proof lanes with:

```bash
./scripts/run_rgc_json_stringify_compound_traversal.sh ci
./scripts/e2e/rgc_json_stringify_compound_traversal_replay.sh ci
./scripts/run_rgc_json_compound_placeholder_closure.sh ci
./scripts/e2e/rgc_json_compound_placeholder_closure_replay.sh ci
```

The lanes emit `json_stringify_compound_traversal_report.json`,
`json_compound_placeholder_closure_report.json`, `run_manifest.json`,
`trace_ids.json`, `events.jsonl`, `commands.txt`, and `step_logs/step_*.log`.

## RGC Zero-Placeholder Gate

The zero-placeholder gate enforces release-time evidence that placeholder,
mock, stub, and TODO-like code paths are either absent from protected surfaces
or explicitly recorded in `waiver_manifest.json`. It emits the audited
`placeholder_gate_report.json` bundle so failed gates have replayable evidence
instead of anonymous placeholder backfills.

To run and replay the gate:

```bash
./scripts/run_rgc_zero_placeholder_gate.sh ci
./scripts/e2e/rgc_zero_placeholder_gate_replay.sh ci
```

## Placeholder Closure Verification

The placeholder closure verification contract defines explicit verification and waiver discipline for closing out the zero-placeholder audit workstream. This contract proves that all audited placeholder/mock/stub findings have been resolved or explicitly waived with proper justification.

To verify the closure contract:

```bash
jq empty docs/rgc_placeholder_closure_verification_v1.json
cargo test --test placeholder_closure_verification
./scripts/run_placeholder_closure_matrix.sh generate
./scripts/run_placeholder_closure_verification.sh verify
./scripts/run_placeholder_closure_bundle.sh bundle
./scripts/run_placeholder_waiver_validation.sh check
```

See [`docs/RGC_PLACEHOLDER_CLOSURE_VERIFICATION_V1.md`](./docs/RGC_PLACEHOLDER_CLOSURE_VERIFICATION_V1.md) for the complete contract specification.

## RGC Cross-Platform Matrix Gate

The cross-platform matrix gate establishes deterministic verification for runtime execution and CLI workflows across Linux/macOS/Windows and x64/arm64 targets. This gate ensures user-facing reliability is proven, not assumed.

To verify the cross-platform matrix:

```bash
./scripts/run_rgc_cross_platform_matrix_gate.sh ci
./scripts/e2e/rgc_cross_platform_matrix_replay.sh matrix
jq empty docs/rgc_cross_platform_matrix_v1.json
```

Matrix artifacts are generated at `artifacts/rgc_cross_platform_matrix/<timestamp>/matrix_summary.json` for each verification run.

See [`docs/RGC_CROSS_PLATFORM_MATRIX_V1.md`](./docs/RGC_CROSS_PLATFORM_MATRIX_V1.md) for the complete contract specification.

## Scientific Contribution Targets Gate

The scientific contribution targets gate tracks FrankenEngine's research deliverables, ensuring that novel contributions become publishable artifacts with reproducible evidence bundles. This gate validates technical reports, external replication claims, and open tool adoption.

To verify scientific contribution targets:

```bash
./scripts/run_scientific_contribution_targets.sh bundle
./scripts/run_scientific_contribution_targets.sh ci
./scripts/e2e/scientific_contribution_targets_replay.sh show
```

Status reports are generated at:
- `artifacts/scientific_contribution_targets/<timestamp>/technical_report_status_report.json`
- `artifacts/scientific_contribution_targets/<timestamp>/external_replication_status_report.json`  
- `artifacts/scientific_contribution_targets/<timestamp>/open_tool_adoption_status_report.json`
- `artifacts/scientific_contribution_targets/<timestamp>/trace_ids.json`

The gate tracks three milestone beads:
- `bd-2501.1` — Publish reproducible technical reports with artifact bundles
- `bd-2501.2` — Achieve externally replicated high-impact claims
- `bd-2501.3` — Release open benchmark or verification tool adopted outside the project

For operator verification:

```bash
jq empty docs/scientific_contribution_targets_v1.json
rch exec -- env RUSTUP_TOOLCHAIN=nightly CARGO_TARGET_DIR=$PWD/target_rch_scientific_contribution_targets_verify CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p frankenengine-engine --test scientific_contribution_targets
```

See [`docs/SCIENTIFIC_CONTRIBUTION_TARGETS_V1.md`](./docs/SCIENTIFIC_CONTRIBUTION_TARGETS_V1.md), [`docs/SCIENTIFIC_REPORT_CATALOG_V1.md`](./docs/SCIENTIFIC_REPORT_CATALOG_V1.md), [`docs/EXTERNAL_REPLICATION_CATALOG_V1.md`](./docs/EXTERNAL_REPLICATION_CATALOG_V1.md), and [`docs/OPEN_TOOL_ADOPTION_CATALOG_V1.md`](./docs/OPEN_TOOL_ADOPTION_CATALOG_V1.md) for complete catalog specifications.

## RGC Docs and Help Surface Audit

The docs and help surface audit ensures that README.md and planned CLI help output stay aligned with commands that are implemented before they are described as shipped. This audit prevents aspirational copy from diverging from runtime behavior.

To verify the docs and help surface contract:

```bash
./scripts/run_rgc_docs_help_surface_audit.sh ci
./scripts/e2e/rgc_docs_help_surface_audit_replay.sh ci
jq empty docs/rgc_docs_help_surface_audit_v1.json
```

The replay wrapper resolves the latest complete audit bundle, warns on incomplete runs, and validates that help output matches the audited contract surface.

Each run also emits `readme_claim_sensitivity_checks.jsonl`, which logs every claim-sensitive README section, matched terms, required proof-state qualifiers, and pass/fail verdict.

Audit artifacts are generated at `artifacts/rgc_docs_help_surface_audit/<timestamp>/docs_help_surface_report.json` for each verification run.

See [`docs/RGC_DOCS_HELP_SURFACE_AUDIT_V1.md`](./docs/RGC_DOCS_HELP_SURFACE_AUDIT_V1.md) for the complete contract specification.

## Deterministic E2E Harness

The deterministic e2e harness validates replay fixtures, structured-log assertions, artifact collection, and signed golden-update metadata for deterministic operator scenarios.

```bash
# CI shortcut (check + test + clippy)
./scripts/run_deterministic_e2e_harness.sh ci
```

Each invocation emits `run_manifest.json`, `events.jsonl`, `commands.txt`, and `step_logs/step_*.log` under `artifacts/deterministic_e2e_harness/<timestamp>/`.

## RGC CLI and Operator Workflow Verification Pack

The CLI and operator workflow verification pack validates the real operator experience of frankenctl workflows across golden-path, failure-path, and observability-mode scenarios with actionable diagnostics. This pack ensures operator workflows are evidence-first and deterministic.

```bash
./scripts/run_rgc_cli_operator_workflow_verification_pack.sh ci
./scripts/e2e/rgc_cli_operator_workflow_verification_pack_replay.sh ci
jq empty docs/rgc_cli_operator_workflow_verification_pack_v1.json
```

Verification artifacts are generated at `artifacts/rgc_cli_operator_workflow_verification_pack/<timestamp>/run_manifest.json`, `artifacts/rgc_cli_operator_workflow_verification_pack/<timestamp>/events.jsonl`, `artifacts/rgc_cli_operator_workflow_verification_pack/<timestamp>/commands.txt`, `artifacts/rgc_cli_operator_workflow_verification_pack/<timestamp>/trace_ids.json`, and `artifacts/rgc_cli_operator_workflow_verification_pack/<timestamp>/step_logs/step_*.log` for each verification run. The workflow also generates support bundle artifacts at `artifacts/frankenctl_cli_workflow/<timestamp>/support_bundle/index.json`.

See [`docs/RGC_CLI_OPERATOR_WORKFLOW_VERIFICATION_PACK_V1.md`](./docs/RGC_CLI_OPERATOR_WORKFLOW_VERIFICATION_PACK_V1.md) for the complete contract specification.

## RGC NPM Compatibility Matrix Gate

Run the npm compatibility matrix gate with:

```bash
./scripts/run_rgc_npm_compatibility_matrix.sh ci
```

Replay a preserved bundle from the latest complete run directory or pin one explicitly:

```bash
RGC_NPM_COMPATIBILITY_MATRIX_REPLAY_RUN_DIR=artifacts/... \
  ./scripts/e2e/rgc_npm_compatibility_matrix_replay.sh ci
```

The machine-readable contract is `docs/rgc_npm_compatibility_matrix_v1.json`.

Artifacts are written under:

- `artifacts/rgc_npm_compatibility_matrix/<timestamp>/npm_compat_matrix_report.json`
- `artifacts/rgc_npm_compatibility_matrix/<timestamp>/trace_ids.json`
- `artifacts/rgc_npm_compatibility_matrix/<timestamp>/run_manifest.json`
- `artifacts/rgc_npm_compatibility_matrix/<timestamp>/events.jsonl`
- `artifacts/rgc_npm_compatibility_matrix/<timestamp>/commands.txt`

Inspect unresolved failures with:

```bash
jq '.unresolved_failures' artifacts/rgc_npm_compatibility_matrix/<timestamp>/npm_compat_matrix_report.json
```

## RGC Observability Publication Policy Gate

Run the observability publication policy gate with:

```bash
./scripts/run_rgc_observability_publication_policy.sh ci
```

Replay the latest complete artifact bundle, or pin an exact preserved run with `RGC_OBSERVABILITY_PUBLICATION_POLICY_REPLAY_RUN_DIR`:

```bash
./scripts/e2e/rgc_observability_publication_policy_replay.sh ci
RGC_OBSERVABILITY_PUBLICATION_POLICY_REPLAY_RUN_DIR=artifacts/rgc_observability_publication_policy/<timestamp> \
  ./scripts/e2e/rgc_observability_publication_policy_replay.sh ci
```

The machine-readable contract is `docs/rgc_observability_publication_policy_v1.json`; complete bundles include `support_bundle_observability_attestation.json`.

## RGC Module Interop Verification Matrix Gate

Run the module interop verification matrix gate with:

```bash
./scripts/run_rgc_module_interop_verification_matrix.sh ci
```

Replay a preserved matrix bundle with:

```bash
RGC_MODULE_INTEROP_MATRIX_REPLAY_RUN_DIR=artifacts/... \
  ./scripts/e2e/rgc_module_interop_verification_matrix_replay.sh
```

The matrix contract is `docs/module_compatibility_matrix_v1.json`.

Artifacts are written under:

- `artifacts/rgc_module_interop_verification_matrix/<timestamp>/run_manifest.json`
- `artifacts/rgc_module_interop_verification_matrix/<timestamp>/events.jsonl`
- `artifacts/rgc_module_interop_verification_matrix/<timestamp>/commands.txt`
- `artifacts/rgc_module_interop_verification_matrix/<timestamp>/module_resolution_trace.jsonl`
- `artifacts/rgc_module_interop_verification_matrix/<timestamp>/trace_ids.json`
- `artifacts/rgc_module_interop_verification_matrix/<timestamp>/step_logs/step_*.log`

Operator verification:

```bash
cat artifacts/rgc_module_interop_verification_matrix/<timestamp>/run_manifest.json
cat artifacts/rgc_module_interop_verification_matrix/<timestamp>/events.jsonl
cat artifacts/rgc_module_interop_verification_matrix/<timestamp>/commands.txt
cat artifacts/rgc_module_interop_verification_matrix/<timestamp>/module_resolution_trace.jsonl
cat artifacts/rgc_module_interop_verification_matrix/<timestamp>/trace_ids.json
cat artifacts/rgc_module_interop_verification_matrix/<timestamp>/step_logs/step_000.log
./scripts/e2e/rgc_module_resolution_trace_contract_smoke.sh
rg -n 'compatibility_disposition|remediation_guidance' \
  docs/module_compatibility_matrix_v1.json
```

The matrix also pins npm-style `pkg.js` / `@scope/pkg.js` extension-probe package entries so nested `./sub` requires stay anchored to the package root. `package.json` `type=module` extensionless relative imports stay fail-closed in `native`/`node_compat`; only the explicit `bun_compat` bridge enables extension probing.

## Installation

### Build From Source

```bash
git clone https://github.com/Dicklesworthstone/franken_engine.git
cd franken_engine
cargo build --release -p frankenengine-engine --bin frankenctl
```

The workspace currently includes these crates:

- `frankenengine-engine`
- `frankenengine-extension-host`
- `frankenengine-test-support`
- `frankenengine-metamorphic`

The source tree currently defines these release binaries:

- `frankenctl` (main CLI binary)
- `franken-react-sidecar`
- `franken-benchmark-evidence-export`

There is no root `install.sh`, prebuilt Linux/macOS/Windows binary bundle, or separate `frankenengine-cli` Cargo package in this repository at this time.

### Optional Operator Stack

```bash
# Required for advanced TUI views
cd /dp/frankentui && cargo build --release

# Required for SQLite-backed replay/evidence stores
cd /dp/frankensqlite && cargo build --release
```

## Quick Start

1. **Create a tiny demo source**
```bash
mkdir -p ./artifacts
printf 'const answer = 40 + 2;\n' > ./demo.js
```

2. **Compile to a deterministic artifact**
```bash
./target/release/frankenctl compile --input ./demo.js --out ./artifacts/demo.compile.json --goal script
./target/release/frankenctl verify compile-artifact --input ./artifacts/demo.compile.json
```

3. **Run the source and persist the execution report**
```bash
./target/release/frankenctl run --input ./demo.js --extension-id demo-ext --out ./artifacts/demo.run.json
```

4. **Verify the basic workflow end-to-end**
```bash
FRANKENCTL_BIN=./target/release/frankenctl ./scripts/e2e/readme_cli_workflow_smoke.sh
```

This workflow creates artifacts under `artifacts/readme_cli_workflow_smoke/<timestamp>/` with signed manifests, structured events, and command transcripts.

## Advanced Verification

Once you've completed the basic quick start and have run some of the proof-suite gates, you can explore advanced verification workflows that depend on captured artifacts:

1. **Analyze captured runtime diagnostics** *(requires runtime_input.json from previous runs)*
```bash
frankenctl doctor --input ./artifacts/runtime_input.json --summary --out-dir ./artifacts/doctor
```

2. **Verify receipt bundles** *(requires verifier artifacts from gate runs)*
```bash
frankenctl verify receipt --input ./artifacts/verifier_input.json --receipt-id rcpt_01J... --summary
frankenctl benchmark score --input ./artifacts/publication_gate_input.json --output ./artifacts/benchmark_score.json
```

3. **Run benchmark and replay workflows** *(requires benchmark artifacts and replay traces)*
```bash
frankenctl benchmark run --profile small --family boot-storm --out-dir ./artifacts/benchmarks
frankenctl benchmark verify --bundle ./artifacts/benchmarks --summary --output ./artifacts/benchmark_verify.json
frankenctl replay run --trace ./artifacts/replay/demo-trace.json --compare-trace ./artifacts/replay/live-trace.json --mode validate --out ./artifacts/replay_report.json
```

4. **Replay captured nondeterminism traces** *(requires sample traces from examples or gate runs)*
```bash
frankenctl replay run --trace ./examples/05_replay_demo/sample_trace.json --mode strict --out ./artifacts/replay_report.json
```

## Command Reference

The command table below documents the `frankenctl` contract and available command surfaces.

| Command | Purpose | Example | Prerequisites |
|---|---|---|---|
| `frankenctl version` | Print CLI schema and binary version | `frankenctl version` | None |
| `frankenctl compile` | Parse and lower source into a versioned compile artifact | `frankenctl compile --input ./demo.js --out ./artifacts/demo.compile.json --goal script` | Source file only |
| `frankenctl run` | Execute source through the orchestrator and emit an execution report | `frankenctl run --input ./demo.js --extension-id demo-ext --out ./artifacts/demo.run.json` | Source file only |
| `frankenctl verify compile-artifact` | Validate compile artifact integrity and schema invariants | `frankenctl verify compile-artifact --input ./artifacts/demo.compile.json` | Compile artifact |
| `frankenctl doctor` | Summarize runtime diagnostics input and emit operator artifacts | `frankenctl doctor --input ./artifacts/runtime_input.json --summary --out-dir ./artifacts/doctor` | Runtime artifacts |
| `frankenctl verify receipt` | Verify a receipt bundle against a specific receipt ID | `frankenctl verify receipt --input ./artifacts/verifier_input.json --receipt-id rcpt_01J...` | Receipt artifacts |
| `frankenctl benchmark run` | Run bundled benchmark families and emit evidence artifacts | `frankenctl benchmark run --profile small --family boot-storm --out-dir ./artifacts/benchmarks` | None |
| `frankenctl benchmark score` | Score a publication-gate input against Node/Bun comparisons | `frankenctl benchmark score --input ./artifacts/publication_gate_input.json --output ./artifacts/benchmark_score.json` | Publication artifacts |
| `frankenctl benchmark verify` | Verify a benchmark claim bundle and render a verdict report | `frankenctl benchmark verify --bundle ./artifacts/benchmarks --summary --output ./artifacts/benchmark_verify.json` | Benchmark artifacts |
| `frankenctl replay run` | Replay a captured nondeterminism trace; `validate` mode compares against `--compare-trace` | `frankenctl replay run --trace ./examples/05_replay_demo/sample_trace.json --mode strict --out ./artifacts/replay_report.json` | Replay traces |

## Operator Documentation

## Parser Operator/Developer Runbook Gate

Run the parser operator/developer runbook gate from the repository root:

```bash
./scripts/run_parser_operator_developer_runbook.sh ci
```

The wrapper uses a repo-local `target_rch_parser_operator_developer_runbook_` target directory and a timeout-safe `cargo test --no-run` compile smoke instead of `cargo check` for the integration-test lane. It emits `run_manifest.json`, `events.jsonl`, `commands.txt`, and `step_logs/step_*.log`; exact preserved-bundle replay requires `step_logs/step_000.log` as part of the complete bundle.

Replay current or preserved evidence with:

```bash
./scripts/e2e/parser_operator_developer_runbook_replay.sh ci
./scripts/e2e/parser_operator_developer_runbook_replay.sh drill
PARSER_OPERATOR_DEVELOPER_RUNBOOK_REPLAY_RUN_DIR=artifacts/parser_operator_developer_runbook/<timestamp> \
  ./scripts/e2e/parser_operator_developer_runbook_replay.sh ci
```

The replay wrapper prints the latest complete artifact bundle, can skip a newer incomplete run directory, and states whether output reflects the current failed invocation or an older complete bundle. Drill mode reuses the latest complete dependency bundles instead of rerunning dependent parser lanes. The emitted `run_manifest.json` includes `operator_verification` commands for both the normal rerun path and the preserved-bundle path without rerunning the lane.

## FRX SSR/Hydration/RSC Compatibility Strategy Gate

Run the deterministic FRX SSR/hydration/RSC compatibility strategy gate with:

```bash
./scripts/run_frx_ssr_hydration_rsc_compatibility_strategy_suite.sh ci
```

Replay its preserved evidence with:

```bash
./scripts/e2e/frx_ssr_hydration_rsc_compatibility_strategy_replay.sh ci
```

The gate writes its manifest to `artifacts/frx_ssr_hydration_rsc_compatibility_strategy/<timestamp>/run_manifest.json`.

## FRX Local Semantic Atlas Gate

Run the deterministic FRX local semantic atlas gate with:

```bash
./scripts/run_frx_local_semantic_atlas_suite.sh ci
```

Replay its preserved evidence with:

```bash
./scripts/e2e/frx_local_semantic_atlas_replay.sh
```

The gate writes its manifest to `artifacts/frx_local_semantic_atlas/<timestamp>/run_manifest.json`.

## FRX Track D WASM Lane + Hybrid Router Sprint Gate

Run the deterministic FRX Track D WASM lane and hybrid router sprint gate with:

```bash
./scripts/run_frx_track_d_wasm_lane_hybrid_router_sprint_suite.sh ci
```

Replay its preserved evidence with:

```bash
./scripts/e2e/frx_track_d_wasm_lane_hybrid_router_sprint_replay.sh
```

The gate writes its manifest to `artifacts/frx_track_d_wasm_lane_hybrid_router_sprint/<timestamp>/run_manifest.json`.

## FRX Track E Verification/Fuzz/Formal Coverage Sprint Gate

Run the deterministic FRX Track E verification/fuzz/formal coverage sprint gate with:

```bash
./scripts/run_frx_track_e_verification_fuzz_formal_coverage_sprint_suite.sh ci
```

Replay its preserved evidence with:

```bash
./scripts/e2e/frx_track_e_verification_fuzz_formal_coverage_sprint_replay.sh
```

The gate writes its manifest to `artifacts/frx_track_e_verification_fuzz_formal_coverage_sprint/<timestamp>/run_manifest.json`.

## FRX Online Regret + Change-Point Demotion Controller Gate

Run the deterministic FRX online regret/change-point demotion controller gate with:

```bash
./scripts/run_frx_online_regret_change_point_demotion_controller_suite.sh ci
```

Replay its preserved evidence with:

```bash
./scripts/e2e/frx_online_regret_change_point_demotion_controller_replay.sh ci
```

The gate writes its manifest to `artifacts/frx_online_regret_change_point_demotion_controller/<timestamp>/run_manifest.json`.

For detailed gate documentation, artifact contracts, and operator workflows, see:

- **[RGC Gates Reference](./docs/operator-gates/RGC_GATES_REFERENCE.md)** - Complete reference for all RGC gate scripts, artifact paths, and replay commands

## Architecture

For system architecture and design details, see:

- **[Architecture Overview](./docs/ARCHITECTURE_OVERVIEW.md)** - High-level system design and component overview  
- **[Runtime Charter](./docs/RUNTIME_CHARTER.md)** - Runtime governance and execution boundaries

## Contributing

For information about contributing to this project, see:

- **[Contributing Guide](./CONTRIBUTING.md)** - Development setup, testing, and submission guidelines

## Unsupported Surfaces

The following operator capabilities are explicitly **not shipped** and should not be 
relied upon in production environments:

### CLI Surfaces Not Recommended for Production Use
- Advanced policy debugging surfaces requiring TEE attestation
- Fleet-wide quarantine orchestration beyond local containment (Note: de-escalation unimplemented - permanent ratchet)  
- Cross-repository governance coordination tools (use asupersync control plane)
- Live policy modification interfaces (use static policy manifests)
- Cryptographic key rotation automation (use dedicated key management)

### Library-Level Capabilities Documented But Not Public API
- Internal execution profile switching without orchestrator mediation
- Direct IR manipulation outside the lowering pipeline contract
- Bypass interfaces for deterministic replay constraints  
- Runtime governance policy overrides without evidence retention
- Evidence artifact tampering or retroactive modification

### Experimental Features Under Active Development
- Multi-tenant isolation boundaries within single runtime instances
- Hardware-specific optimization targeting (beyond baseline profiles)
- Third-party evidence verifier plugin architecture
- Real-time adversarial policy adaptation
- Cross-engine differential execution with live workloads

**Important**: Undocumented CLI commands, internal library interfaces, and 
experimental flags may change or be removed without notice. For production 
integration, use only the explicitly documented surfaces listed in the 
[Quick Example](#quick-example) section.

**Support Contract**: Unsupported surface usage voids reproduction assistance. 
Submit issues only for documented surface behaviors with reproducible artifact 
bundles following the templates in [`docs/templates/`](./docs/templates/).

## Limitations

- High-security mode adds measurable overhead on latency-sensitive low-risk workloads.
- Capability-typed TS-to-IR extension onboarding is not shipped as an end-to-end contract; current capability checks cover selected runtime hostcall/import boundaries.
- Deterministic replay and evidence retention increase storage footprint.
- Full Node ecosystem compatibility remains an active target; edge behavior differences can still appear in low-level module or process APIs.
- Fleet-level immune features assume stable cryptographic identity and time synchronization across participating nodes.

## FAQ

### 1. Is FrankenEngine a Node replacement?
For extension-heavy, high-trust workloads, yes. For broad legacy compatibility-only use cases, `franken_node` is the product layer that provides migration paths.

### 2. Do I need asupersync to use this?
Yes, for full control-plane guarantees. FrankenEngine can run with reduced local mode, but constitutional guarantees require `/dp/asupersync` integration.

To verify both build modes, run `./scripts/test_standalone_build.sh ci`. That gate records
artifacts under `artifacts/standalone_build_gate/<timestamp>/`, sends every heavy Cargo lane
through `rch`, and treats the standalone mode as the blocking gate:

- `cargo check -p frankenengine-engine --no-default-features`
- `cargo test -p frankenengine-engine --no-default-features`
- `cargo check -p frankenengine-engine --all-features`

If the sibling `/dp` dependencies needed for full integration are unavailable, the script records
that lane as skipped in the manifest instead of pretending the repo is fully integrated.
The canonical dependency-isolation contract for this split lives in
`docs/CROSS_REPO_DEPENDENCY_ISOLATION_V1.md` and `docs/cross_repo_dependency_isolation_v1.json`.

### 3. Can I run without frankentui?
Yes for basic CLI workflows. Advanced operator views, replay dashboards, and policy explanation consoles use `/dp/frankentui`.

### 4. Why require frankensqlite for SQLite workloads?
It enforces shared persistence contracts and conformance behavior across replay, evidence, benchmark, and control artifacts.

### 5. How are false positives controlled?
Through explicit expected-loss matrices, sequential testing boundaries, calibrated posterior models, and shadow promotion gates.

### 6. What does deterministic replay guarantee exactly?
The target contract is identical replay from fixed code, policy, model snapshot, evidence stream, and randomness transcript. Current proof covers replay APIs and a targeted coverage gate; end-to-end byte-identical high-severity execution artifacts remain a tracked target.

### 7. Can I verify your benchmark claims independently?
Yes. The benchmark harness, manifests, and artifact bundles are designed for third-party reproduction.

### 8. How fast is containment in practice?
Operational target is at or below 250ms median from high-risk threshold crossing to containment action under defined load envelopes.

## About Contributions

> *About Contributions:* Please don't take this the wrong way, but I do not accept outside contributions for any of my projects. I simply don't have the mental bandwidth to review anything, and it's my name on the thing, so I'm responsible for any problems it causes; thus, the risk-reward is highly asymmetric from my perspective. I'd also have to worry about other "stakeholders," which seems unwise for tools I mostly make for myself for free. Feel free to submit issues, and even PRs if you want to illustrate a proposed fix, but know I won't merge them directly. Instead, I'll have Claude or Codex review submissions via `gh` and independently decide whether and how to address them. Bug reports in particular are welcome. Sorry if this offends, but I want to avoid wasted time and hurt feelings. I understand this isn't in sync with the prevailing open-source ethos that seeks community contributions, but it's the only way I can move at this velocity and keep my sanity.

## License

MIT, see [LICENSE](./LICENSE).
