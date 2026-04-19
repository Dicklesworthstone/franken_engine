# FrankenEngine

<div align="center">
  <img src="franken_engine_illustration.webp" alt="FrankenEngine - Native Rust runtime for high-trust extension workloads">
</div>

<div align="center">

[![Rust 2024](https://img.shields.io/badge/Rust-2024-orange.svg)](https://www.rust-lang.org/)
[![Unsafe Forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://doc.rust-lang.org/reference/unsafe-keyword.html)
[![Deterministic Replay](https://img.shields.io/badge/replay-deterministic-blue.svg)](./PLAN_TO_CREATE_FRANKEN_ENGINE.md)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

</div>

Native Rust runtime for adversarial extension workloads, with deterministic replay, cryptographic decision receipts, and fleet-scale containment.

<div align="center">
<h3>Quick Install</h3>

```bash
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/franken_engine/main/install.sh?$(date +%s)" | bash
```

<p><em>Linux, macOS, and Windows support with architecture-aware binaries.</em></p>
</div>

---

## TL;DR

### The Problem
Node and Bun are fast enough for many workloads, but extension-heavy agent systems need a different default posture: active containment, deterministic forensics, and explicit runtime authority boundaries.

### The Solution
FrankenEngine provides one native baseline interpreter with deterministic and throughput execution profiles, a probabilistic guardplane with expected-loss actioning, deterministic replay for high-severity decisions, and signed evidence contracts for every high-impact containment event.

### Why Use FrankenEngine?

| Capability | What You Get In Practice |
|---|---|
| Native execution profiles | `baseline_deterministic_profile` for conservative control paths, `baseline_throughput_profile` for throughput-heavy paths, and `adaptive_profile_router` when policy routing is enabled |
| Probabilistic Guardplane | Bayesian risk updates and e-process boundaries that trigger `allow/challenge/sandbox/suspend/terminate/quarantine` |
| Deterministic replay | Bit-stable replay for high-severity decision paths with counterfactual policy simulation |
| Cryptographic governance | Signed decision receipts with transparency-log proofs and optional TEE attestation bindings |
| Fleet immune system | Quarantine and revocation propagation with bounded convergence SLOs |
| Capability-typed execution | TS-first workflow that compiles to capability-typed IR with ambient-authority rejection |
| Cross-repo constitution | Control plane on `/dp/asupersync`, TUI on `/dp/frankentui`, SQLite on `/dp/frankensqlite` |
| Evidence-first operations | Every published performance and security claim ships with reproducible artifact bundles |

## Quick Example

The shipped `frankenctl` CLI is intentionally narrower than the long-term
operator roadmap. Today the binary exposes `version`, `compile`, `run`,
`doctor`, `verify`, `benchmark`, and `replay`; other operator surfaces stay
documented as planned/library-level capabilities until they are actually
shipped.

```bash
# 1) Install and verify
frankenctl version

# 2) Create a tiny source file and artifact directory
mkdir -p ./artifacts
printf 'const answer = 40 + 2;\n' > ./demo.js

# 3) Compile source to a versioned artifact
frankenctl compile --input ./demo.js --out ./artifacts/demo.compile.json --goal script

# 4) Verify the compile artifact contract
frankenctl verify compile-artifact --input ./artifacts/demo.compile.json

# 5) Execute the same source through the orchestrator
frankenctl run --input ./demo.js --extension-id demo-ext --out ./artifacts/demo.run.json

# 6) Replay execution with validation mode
frankenctl replay run --trace ./artifacts/replay/demo-trace.json --mode validate --out ./artifacts/replay_report.json
```

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
| Deterministic replay for high-severity decisions | Built in, mandatory release gate | External tooling only | External tooling only |
| Probabilistic containment policy | Built in guardplane | Not default runtime behavior | Not default runtime behavior |
| Cryptographic decision receipts | First-class runtime artifact | Not a core runtime primitive | Not a core runtime primitive |
| Fleet quarantine convergence model | Explicit SLO + fault-injection gates | App-specific integration | App-specific integration |
| Capability-typed extension contract | Native IR contract | Not native to runtime | Not native to runtime |
| Cross-runtime lockstep oracle | Built in Node/Bun differential harness | N/A | N/A |

## Build Modes

FrankenEngine supports two build modes to accommodate different development and deployment environments:

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
For production deployments with the complete asupersync ecosystem:

```bash
# Build with all external dependencies
cargo check --all-features
cargo build --all-features --release

# Test full integration
cargo test --all-features
```

In full integration mode:
- Complete governance and policy enforcement
- Cross-repository coordination enabled
- TEE attestation and fleet quarantine available
- Cryptographic decision receipts with audit trails

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

## Lowering Gap Truth Invariant

The lowering gap truth invariant defines the authoritative relationship between lowering status fields and execution-readiness flags. This contract ensures that `status`, `parser_ready_syntax`, `execution_ready_semantics`, and prose fields cannot report mutually incompatible states in the lowering gap inventory.

To verify the invariant contract:

```bash
./scripts/run_lowering_gap_truth_invariant.sh ci
./scripts/e2e/lowering_gap_truth_invariant_replay.sh ci
```

See [`docs/LOWERING_GAP_TRUTH_INVARIANT_V1.md`](./docs/LOWERING_GAP_TRUTH_INVARIANT_V1.md) for the complete invariant specification.

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

The docs and help surface audit ensures that README.md and frankenctl --help output accurately reflect the commands that actually parse and run in the shipped implementation. This audit prevents aspirational copy from diverging from runtime behavior.

To verify the docs and help surface contract:

```bash
./scripts/run_rgc_docs_help_surface_audit.sh ci
./scripts/e2e/rgc_docs_help_surface_audit_replay.sh ci
jq empty docs/rgc_docs_help_surface_audit_v1.json
```

The replay wrapper resolves the latest complete audit bundle, warns on incomplete runs, and validates that help output matches the audited contract surface.

Audit artifacts are generated at `artifacts/rgc_docs_help_surface_audit/<timestamp>/docs_help_surface_report.json` for each verification run.

See [`docs/RGC_DOCS_HELP_SURFACE_AUDIT_V1.md`](./docs/RGC_DOCS_HELP_SURFACE_AUDIT_V1.md) for the complete contract specification.

## Installation

### Option 1: One-Line Installer

```bash
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/franken_engine/main/install.sh" | bash
```

### Option 2: Cargo

```bash
cargo install frankenengine-cli
```

### Option 3: Build From Source

```bash
git clone https://github.com/Dicklesworthstone/franken_engine.git
cd franken_engine
cargo build --release --workspace
./target/release/frankenctl version
```

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
frankenctl compile --input ./demo.js --out ./artifacts/demo.compile.json --goal script
frankenctl verify compile-artifact --input ./artifacts/demo.compile.json
```

3. **Run the source and persist the execution report**
```bash
frankenctl run --input ./demo.js --extension-id demo-ext --out ./artifacts/demo.run.json
```

4. **Summarize a captured runtime snapshot**
```bash
frankenctl doctor --input ./artifacts/runtime_input.json --summary --out-dir ./artifacts/doctor
```

5. **Verify receipt bundles and benchmark publication inputs**
```bash
frankenctl verify receipt --input ./artifacts/verifier_input.json --receipt-id rcpt_01J... --summary
frankenctl benchmark score --input ./artifacts/publication_gate_input.json --output ./artifacts/benchmark_score.json
```

6. **Run benchmark and replay workflows when you have the required artifacts**
```bash
frankenctl benchmark run --profile small --family boot-storm --out-dir ./artifacts/benchmarks
frankenctl benchmark verify --bundle ./artifacts/benchmarks --summary --output ./artifacts/benchmark_verify.json
frankenctl replay run --trace ./artifacts/replay/demo-trace.json --compare-trace ./artifacts/replay/live-trace.json --mode validate --out ./artifacts/replay_report.json
```

## Command Reference

The command table below is the current shipped `frankenctl` contract. Treat
workspace init, promotion, revocation repair, lockstep diffing, TUI, and API
serving as roadmap/library surfaces until dedicated CLI beads land them.

| Command | Purpose | Example |
|---|---|---|
| `frankenctl version` | Print the shipped CLI schema/binary version | `frankenctl version` |
| `frankenctl compile` | Parse and lower source into a versioned compile artifact | `frankenctl compile --input ./demo.js --out ./artifacts/demo.compile.json --goal script` |
| `frankenctl run` | Execute source through the orchestrator and emit an execution report | `frankenctl run --input ./demo.js --extension-id demo-ext --out ./artifacts/demo.run.json` |
| `frankenctl doctor` | Summarize runtime diagnostics input and emit operator artifacts | `frankenctl doctor --input ./artifacts/runtime_input.json --summary --out-dir ./artifacts/doctor` |
| `frankenctl verify compile-artifact` | Validate compile artifact integrity and schema invariants | `frankenctl verify compile-artifact --input ./artifacts/demo.compile.json` |
| `frankenctl verify receipt` | Verify a receipt bundle against a specific receipt ID | `frankenctl verify receipt --input ./artifacts/verifier_input.json --receipt-id rcpt_01J... --summary` |
| `frankenctl benchmark run` | Run bundled benchmark families and emit evidence artifacts | `frankenctl benchmark run --profile small --family boot-storm --out-dir ./artifacts/benchmarks` |
| `frankenctl benchmark score` | Score a publication-gate input against Node/Bun comparisons | `frankenctl benchmark score --input ./artifacts/publication_gate_input.json --output ./artifacts/benchmark_score.json` |
| `frankenctl benchmark verify` | Verify a benchmark claim bundle and render a verdict report | `frankenctl benchmark verify --bundle ./artifacts/benchmarks --summary --output ./artifacts/benchmark_verify.json` |
| `frankenctl replay run` | Replay a captured nondeterminism trace; `validate` mode compares it against `--compare-trace` | `frankenctl replay run --trace ./artifacts/replay/demo-trace.json --compare-trace ./artifacts/replay/live-trace.json --mode validate --out ./artifacts/replay_report.json` |

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

For detailed gate documentation, artifact contracts, and operator workflows, see:

- **[RGC Gates Reference](./docs/operator-gates/RGC_GATES_REFERENCE.md)** - Complete reference for all RGC gate scripts, artifact paths, and replay commands

## Architecture

For system architecture and design details, see:

- **[Architecture Overview](./docs/ARCHITECTURE_OVERVIEW.md)** - High-level system design and component overview  
- **[Runtime Charter](./docs/RUNTIME_CHARTER.md)** - Runtime governance and execution boundaries

## Contributing

For information about contributing to this project, see:

- **[Contributing Guide](./CONTRIBUTING.md)** - Development setup, testing, and submission guidelines

## Limitations

- High-security mode adds measurable overhead on latency-sensitive low-risk workloads.
- Capability-typed extension onboarding requires explicit manifests and policy declarations; this is extra setup for small prototypes.
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
Given fixed code, policy, model snapshot, evidence stream, and randomness transcript, high-severity decision execution replays identically.

### 7. Can I verify your benchmark claims independently?
Yes. The benchmark harness, manifests, and artifact bundles are designed for third-party reproduction.

### 8. How fast is containment in practice?
Operational target is at or below 250ms median from high-risk threshold crossing to containment action under defined load envelopes.

## About Contributions

> *About Contributions:* Please don't take this the wrong way, but I do not accept outside contributions for any of my projects. I simply don't have the mental bandwidth to review anything, and it's my name on the thing, so I'm responsible for any problems it causes; thus, the risk-reward is highly asymmetric from my perspective. I'd also have to worry about other "stakeholders," which seems unwise for tools I mostly make for myself for free. Feel free to submit issues, and even PRs if you want to illustrate a proposed fix, but know I won't merge them directly. Instead, I'll have Claude or Codex review submissions via `gh` and independently decide whether and how to address them. Bug reports in particular are welcome. Sorry if this offends, but I want to avoid wasted time and hurt feelings. I understand this isn't in sync with the prevailing open-source ethos that seeks community contributions, but it's the only way I can move at this velocity and keep my sanity.

## License

MIT, see [LICENSE](./LICENSE).