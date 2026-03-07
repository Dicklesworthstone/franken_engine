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
frankenctl replay run --trace ./artifacts/replay/demo-trace.json --mode validate --out ./artifacts/replay_report.json
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
| `frankenctl replay run` | Replay a captured nondeterminism trace in strict, best-effort, or validate mode | `frankenctl replay run --trace ./artifacts/replay/demo-trace.json --mode validate --out ./artifacts/replay_report.json` |

## RGC Docs and Help Surface Audit

The shipped CLI contract above is guarded by an explicit docs/help audit pack so
README examples do not drift back toward aspirational subcommands.

- `docs/RGC_DOCS_HELP_SURFACE_AUDIT_V1.md`
- `docs/rgc_docs_help_surface_audit_v1.json`
- `./scripts/run_rgc_docs_help_surface_audit.sh ci`
- `./scripts/e2e/rgc_docs_help_surface_audit_replay.sh ci`

## Execution Profile Contract Migration

Operator-facing execution labels now use the honest profile contract:
`baseline_deterministic_profile`, `baseline_throughput_profile`, and
`adaptive_profile_router`.

Legacy lineage labels such as `quickjs_inspired_native` and
`v8_inspired_native` remain accepted on input for migration purposes. The
mapping and rollout guidance live in
[`docs/RGC_EXECUTION_PROFILE_CONTRACT_MIGRATION_V1.md`](./docs/RGC_EXECUTION_PROFILE_CONTRACT_MIGRATION_V1.md).

## Configuration

`franken-engine.toml`

```toml
# Runtime identity and environment
[runtime]
cluster = "prod"
zone = "us-east-1"
mode = "secure"

# Select execution profiles and router policy
[execution_profiles]
default = "adaptive_profile_router"
baseline_deterministic_profile_enabled = true
baseline_throughput_profile_enabled = true

[router]
policy = "risk_aware"
fallback_lane = "baseline_deterministic_profile"

# Guardplane decision settings
[guardplane]
enabled = true
posterior_model = "bayes-online-v1"
sequential_test = "e_process"

[guardplane.loss]
allow = 0
warn = 5
challenge = 15
sandbox = 30
suspend = 60
terminate = 90
quarantine = 100

# Cryptographic decision receipts
[receipts]
enabled = true
transparency_log = "sqlite"
require_signature = true

# Optional TEE attestation binding for high-impact actions
[receipts.attestation]
enabled = true
min_quote_freshness_seconds = 300
fail_mode = "safe"

# Deterministic replay requirements
[replay]
enabled = true
record_randomness_transcript = true
require_snapshot_signature = true

# Control-plane substrate from asupersync
[control_plane]
provider = "asupersync"
path = "/dp/asupersync"
require_cx_threading = true
require_cancel_drain_finalize = true

# SQLite-backed persistence via frankensqlite
[storage]
provider = "frankensqlite"
path = "/var/lib/franken_engine/runtime.db"
wal_mode = true

# See docs/adr/ADR-0004-frankensqlite-reuse-scope.md for required
# SQLite substrate scope, WAL/PRAGMA ownership, and exception process.
# See docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md for store-by-store
# mapping (replay/evidence/benchmark/policy/witness/lineage/provenance/specialization).

# Operator TUI surfaces via frankentui
[ui]
provider = "frankentui"
default_view = "control-dashboard"

# See docs/adr/ADR-0003-frankentui-reuse-scope.md for advanced
# operator-surface scope and exception handling.

# API layer conventions from fastapi_rust
[api]
enabled = true
bind = "127.0.0.1:8787"
transport = "http"

# See docs/adr/ADR-0002-fastapi-rust-reuse-scope.md for required
# reuse boundaries and approved exception process.

# Scheduler and resource governance
[scheduler]
lanes = ["cancel", "timed", "ready", "background"]
default_cpu_budget_millis = 50
default_memory_budget_mb = 128
```

## Architecture

```text
                    +-----------------------------------+
                    |           franken_node            |
                    |  compatibility + product surface  |
                    +----------------+------------------+
                                     |
                                     v
+-------------------------------------------------------------------+
|                           FrankenEngine                            |
|                                                                   |
|  +-------------------+      +----------------------------------+  |
|  | Native Data Plane |      |  Control Plane (Constitutional) |  |
|  |-------------------|      |----------------------------------|  |
|  | parser + IR       |      | Cx capability contracts          |  |
|  | baseline interp.  |<---->| decision contracts               |  |
|  | + profile router  |      | evidence + receipts              |  |
|  | GC + scheduler    |      | cancel -> drain -> finalize      |  |
|  | module runtime    |      |                                  |  |
|  +-------------------+      +----------------------------------+  |
|            |                                   |                  |
+------------+-----------------------------------+------------------+
             |                                   |
             v                                   v
  +---------------------+             +--------------------------+
  | /dp/frankensqlite   |             | /dp/frankentui          |
  | replay/evidence DB  |             | operator dashboards/TUI |
  +---------------------+             +--------------------------+
             |
             v
  +---------------------+
  | /dp/asupersync      |
  | kernel/decision/    |
  | evidence/frankenlab |
  +---------------------+
```

## Deterministic E2E Harness

`bd-8no5` establishes a deterministic harness substrate in `crates/franken-engine/src/e2e_harness.rs` with replay verification, structured-log assertions, artifact collection, and signed golden-update metadata.

Run harness checks/tests through `rch` (CPU-intensive commands are offloaded):

```bash
# check test targets for frankenengine-engine
./scripts/run_deterministic_e2e_harness.sh check

# run deterministic harness integration tests
./scripts/run_deterministic_e2e_harness.sh test

# strict lint pass for harness test target
./scripts/run_deterministic_e2e_harness.sh clippy

# CI shortcut (check + test + clippy)
./scripts/run_deterministic_e2e_harness.sh ci
```

Each invocation emits deterministic lane artifacts under
`artifacts/deterministic_e2e_harness/<timestamp>/`:
- `run_manifest.json` (trace/decision/policy IDs + deterministic environment + replay command)
- `events.jsonl` (structured lane completion event)
- `commands.txt` (exact executed command transcript)
- `step_logs/step_*.log` (per-step `rch` logs with timeout and remote-exit diagnostics)

Create a signed golden-update artifact when intentionally accepting an output digest change:

```bash
./scripts/sign_e2e_golden_update.sh \
  --fixture-id minimal-fixture \
  --previous-digest 2f1a... \
  --next-digest 9b4e... \
  --run-id run-minimal-fixture-9b4e... \
  --signer maintainer@franken.engine \
  --signature sig:deadbeef \
  --rationale "policy update changed expected event stream"
```

The command writes a deterministic JSON artifact under
`crates/franken-engine/tests/artifacts/golden-updates/`.

## FRX End-to-End Scenario Matrix Gate

`bd-mjh3.20.3` defines deterministic baseline, differential, and chaos lanes for
core user-journey coverage (`render`, `update`, `hydration`, `navigation`,
`error_recovery`) plus degraded/adversarial modes, with fail-closed linkage to
unit anchors and invariant references.

```bash
# FRX end-to-end scenario matrix gate (rch-backed check + test + clippy)
./scripts/run_frx_end_to_end_scenario_matrix_suite.sh ci

# deterministic replay wrapper
./scripts/e2e/frx_end_to_end_scenario_matrix_replay.sh ci
```

Contract and vectors:

- [`docs/FRX_END_TO_END_SCENARIO_MATRIX_V1.md`](./docs/FRX_END_TO_END_SCENARIO_MATRIX_V1.md)
- `docs/frx_end_to_end_scenario_matrix_v1.json`
- `crates/franken-engine/tests/frx_end_to_end_scenario_matrix.rs`
- `crates/franken-engine/src/e2e_harness.rs`

Artifacts are written under:

- `artifacts/frx_end_to_end_scenario_matrix/<timestamp>/run_manifest.json`
- `artifacts/frx_end_to_end_scenario_matrix/<timestamp>/events.jsonl`
- `artifacts/frx_end_to_end_scenario_matrix/<timestamp>/commands.txt`

## FRX Milestone/Release Test-Evidence Integrator Gate

`bd-mjh3.20.6` binds FRX test-quality evidence into cut-line and release
promotion decisions with fail-closed behavior for missing, stale, malformed, or
unsigned signal artifacts.

```bash
# FRX milestone/release test-evidence integrator gate (rch-backed check + test + clippy)
./scripts/run_frx_milestone_release_test_evidence_integrator_suite.sh ci

# deterministic replay wrapper
./scripts/e2e/frx_milestone_release_test_evidence_integrator_replay.sh ci
```

Contract and vectors:

- [`docs/FRX_MILESTONE_RELEASE_TEST_EVIDENCE_INTEGRATOR_V1.md`](./docs/FRX_MILESTONE_RELEASE_TEST_EVIDENCE_INTEGRATOR_V1.md)
- `docs/frx_milestone_release_test_evidence_integrator_v1.json`
- `crates/franken-engine/src/milestone_release_test_evidence_integrator.rs`
- `crates/franken-engine/tests/frx_milestone_release_test_evidence_integrator.rs`

Artifacts are written under:

- `artifacts/frx_milestone_release_test_evidence_integrator/<timestamp>/run_manifest.json`
- `artifacts/frx_milestone_release_test_evidence_integrator/<timestamp>/events.jsonl`
- `artifacts/frx_milestone_release_test_evidence_integrator/<timestamp>/commands.txt`

## Parser Phase0 Gate

`bd-3spt` parser phase0 gate validates scalar-reference parser determinism, semantic fixture hashes, and artifact-bundle generation.

```bash
# parser phase0 CI gate (check + focused parser tests + artifact bundle)
./scripts/run_parser_phase0_gate.sh ci
```

Grammar-closure backlog contract (`bd-2mds.1.1.1`) is tracked in
[`docs/PARSER_GRAMMAR_CLOSURE_BACKLOG.md`](./docs/PARSER_GRAMMAR_CLOSURE_BACKLOG.md)
with machine-checked catalog + replay coverage in:
- `crates/franken-engine/tests/fixtures/parser_grammar_closure_backlog.json`
- `crates/franken-engine/tests/parser_grammar_closure_backlog.rs`

Normative/adversarial corpus expansion + deterministic reducer promotion policy
(`bd-2mds.1.1.4`) is tracked in
[`docs/PARSER_GRAMMAR_CLOSURE_BACKLOG.md`](./docs/PARSER_GRAMMAR_CLOSURE_BACKLOG.md)
with contract vectors in:
- `crates/franken-engine/tests/fixtures/parser_phase0_semantic_fixtures.json`
- `crates/franken-engine/tests/fixtures/parser_phase0_adversarial_fixtures.json`
- `crates/franken-engine/tests/fixtures/parser_reducer_promotion_policy.json`
- `crates/franken-engine/tests/parser_corpus_promotion_policy.rs`
- `scripts/run_parser_reducer_promotion_gate.sh` + `scripts/e2e/parser_reducer_promotion_replay.sh`

Canonical AST schema/hash contract (`bd-2mds.1.1.2`) is tracked in
[`docs/PARSER_CANONICAL_AST_SCHEMA.md`](./docs/PARSER_CANONICAL_AST_SCHEMA.md)
with compatibility vectors in:
- `crates/franken-engine/tests/parser_trait_ast.rs`
- `crates/franken-engine/tests/ast_integration.rs`

Canonical Parse Event IR schema/hash contract (`bd-2mds.1.4.1`) is tracked in
[`docs/PARSER_EVENT_IR_SCHEMA.md`](./docs/PARSER_EVENT_IR_SCHEMA.md)
with compatibility vectors in:
- `crates/franken-engine/src/parser.rs` (unit coverage for schema + deterministic event emission)
- `crates/franken-engine/tests/parser_trait_ast.rs`

Deterministic event->AST materializer contract (`bd-2mds.1.4.3`) is tracked in
[`docs/PARSER_EVENT_IR_SCHEMA.md`](./docs/PARSER_EVENT_IR_SCHEMA.md)
with compatibility vectors and replay lane artifacts in:
- `crates/franken-engine/src/parser.rs` (materializer core + stable node-id witness generation)
- `crates/franken-engine/tests/parser_trait_ast.rs` (event->AST parity/tamper/replay vectors)
- `scripts/run_parser_event_materializer_lane.sh` + `scripts/e2e/parser_event_materializer_replay.sh` (structured lane manifests/events)

Core event->AST equivalence harness + deterministic replay contract (`bd-2mds.1.4.4.1`)
is tracked in
[`docs/PARSER_EVENT_AST_EQUIVALENCE_REPLAY_CONTRACT.md`](./docs/PARSER_EVENT_AST_EQUIVALENCE_REPLAY_CONTRACT.md)
with fixture-driven vectors and lane artifacts in:
- `crates/franken-engine/tests/fixtures/parser_event_ast_equivalence_v1.json`
- `crates/franken-engine/tests/parser_event_ast_equivalence.rs`
- `scripts/run_parser_event_ast_equivalence.sh` + `scripts/e2e/parser_event_ast_equivalence_replay.sh`

Canonical parser diagnostics taxonomy + normalization contract (`bd-2mds.1.1.3`)
is tracked in
[`docs/PARSER_DIAGNOSTICS_TAXONOMY.md`](./docs/PARSER_DIAGNOSTICS_TAXONOMY.md)
with compatibility vectors in:
- `crates/franken-engine/src/parser.rs` (taxonomy + normalized envelope unit coverage)
- `crates/franken-engine/tests/parser_trait_ast.rs` (metadata stability + pinned normalized-diagnostic hashes)

Byte-classification + UTF-8 boundary-safe scanner contract (`bd-2mds.1.3.1`)
is implemented in:
- `crates/franken-engine/src/parser.rs` (`LEX_BYTE_CLASS_TABLE`, `Utf8BoundarySafeScanner`, ASCII scalar-parity tests)
- `crates/franken-engine/tests/parser_trait_ast.rs` (UTF-8 budget witness compatibility vector)

```bash
# replay one grammar family deterministically (via rch)
PARSER_GRAMMAR_FAMILY=statement.control_flow rch exec -- \
  env RUSTUP_TOOLCHAIN=nightly CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_parser_phase0_gate \
  cargo test -p frankenengine-engine --test parser_grammar_closure_backlog \
  parser_grammar_closure_backlog_fixtures_are_replayable_by_family -- --nocapture

# run canonical AST contract vectors (via rch)
rch exec -- env RUSTUP_TOOLCHAIN=nightly \
  CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_parser_ast_contract \
  cargo test -p frankenengine-engine --test parser_trait_ast --test ast_integration

# run parser diagnostics taxonomy/normalization compatibility vectors (via rch)
rch exec -- env RUSTUP_TOOLCHAIN=nightly \
  CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_parser_diagnostics_contract \
  cargo test -p frankenengine-engine --test parser_trait_ast

# run normative/adversarial corpus + reducer promotion policy vectors (via rch)
rch exec -- env RUSTUP_TOOLCHAIN=nightly \
  CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_parser_reducer_promotion \
  cargo test -p frankenengine-engine --test parser_corpus_promotion_policy

# run deterministic parser event->AST materializer lane (rch-backed)
./scripts/run_parser_event_materializer_lane.sh ci

# one-command deterministic replay for materializer lane
./scripts/e2e/parser_event_materializer_replay.sh

# run core event->AST equivalence harness + deterministic replay contract lane (rch-backed)
./scripts/run_parser_event_ast_equivalence.sh ci

# one-command deterministic replay for event->AST equivalence lane
./scripts/e2e/parser_event_ast_equivalence_replay.sh

# run deterministic reducer-promotion gate + one-command replay lane
./scripts/run_parser_reducer_promotion_gate.sh ci
./scripts/e2e/parser_reducer_promotion_replay.sh
```

Gate run manifests are written under `artifacts/parser_phase0_gate/<timestamp>/run_manifest.json`.

## Lowering Gap Inventory

`bd-1lsy.2.7` publishes a deterministic lowering-gap ledger that makes parser-ready versus execution-ready semantics explicit for the current placeholder and fail-closed lowering paths.

```bash
# deterministic lowering-gap inventory artifact bundle (rch-backed)
./scripts/e2e/lowering_gap_inventory_replay.sh
```

Artifacts are written under:

- `artifacts/lowering_gap_inventory/<timestamp>/lowering_gap_inventory.json`
- `artifacts/lowering_gap_inventory/<timestamp>/run_manifest.json`
- `artifacts/lowering_gap_inventory/<timestamp>/events.jsonl`
- `artifacts/lowering_gap_inventory/<timestamp>/commands.txt`
Event->AST equivalence manifests are written under
`artifacts/parser_event_ast_equivalence/<timestamp>/run_manifest.json`.
Reducer promotion manifests are written under
`artifacts/parser_reducer_promotion/<timestamp>/run_manifest.json`.

## Parser Failover Controls Gate

`bd-2mds.1.5.4.1` adds deterministic fallback trigger semantics and serial
failover decision logging for parallel parser runs.

```bash
# parser failover controls gate (rch-backed check + focused failover drills + clippy)
./scripts/run_parser_failover_controls_gate.sh ci
```

Failover artifacts are written under:

- `artifacts/parser_failover_controls/<timestamp>/run_manifest.json`
- `artifacts/parser_failover_controls/<timestamp>/events.jsonl`
- `artifacts/parser_failover_controls/<timestamp>/commands.txt`

## Parser Parallel Interference Gate

`bd-2mds.1.5.4.2` runs worker/seed parity matrices and adversarial
determinism stress checks for the parallel parser path, with witness-diff
explanations and replay bundles for mismatches.

```bash
# parser parallel interference gate (rch-backed check + stress tests + clippy)
./scripts/run_parser_parallel_interference_gate.sh ci
```

Contract and vectors:

- [`docs/PARSER_PARALLEL_INTERFERENCE_GATE.md`](./docs/PARSER_PARALLEL_INTERFERENCE_GATE.md)
- `crates/franken-engine/tests/parallel_interference_gate_integration.rs`
- `crates/franken-engine/tests/parallel_parser_integration.rs`

Artifacts are written under:

- `artifacts/parser_parallel_interference/<timestamp>/run_manifest.json`
- `artifacts/parser_parallel_interference/<timestamp>/events.jsonl`
- `artifacts/parser_parallel_interference/<timestamp>/commands.txt`

## Parser Cross-Architecture Reproducibility Matrix Gate

`bd-2mds.1.7.2` compares `x86_64` and `aarch64` parser-lane evidence for
deterministic reproducibility, classifies drift with explicit severity, and
fails closed on unresolved critical deltas in strict matrix mode.
`run_manifest.json` and `matrix_summary.json` include deterministic
`matrix_input_status` (`pending_upstream_matrix`, `incomplete_matrix`,
`blocked_critical_deltas`, `ready_for_external_rerun`) for downstream gating.

```bash
# cross-arch matrix contract/test gate (rch-backed check + test + clippy)
./scripts/run_parser_cross_arch_repro_matrix.sh ci

# strict matrix evaluation (requires explicit x86_64 + arm64 lane manifests)
PARSER_CROSS_ARCH_X86_EVENT_AST_MANIFEST=artifacts/.../x86_event_ast/run_manifest.json \
PARSER_CROSS_ARCH_ARM64_EVENT_AST_MANIFEST=artifacts/.../arm64_event_ast/run_manifest.json \
PARSER_CROSS_ARCH_X86_PARALLEL_INTERFERENCE_MANIFEST=artifacts/.../x86_parallel/run_manifest.json \
PARSER_CROSS_ARCH_ARM64_PARALLEL_INTERFERENCE_MANIFEST=artifacts/.../arm64_parallel/run_manifest.json \
./scripts/run_parser_cross_arch_repro_matrix.sh matrix

# one-command replay wrapper
./scripts/e2e/parser_cross_arch_repro_matrix_replay.sh
```

Contract and vectors:

- [`docs/PARSER_CROSS_ARCH_REPRO_MATRIX.md`](./docs/PARSER_CROSS_ARCH_REPRO_MATRIX.md)
- `crates/franken-engine/tests/fixtures/parser_cross_arch_repro_matrix_v1.json`
- `crates/franken-engine/tests/parser_cross_arch_repro_matrix.rs`

Artifacts are written under:

- `artifacts/parser_cross_arch_repro_matrix/<timestamp>/run_manifest.json`
- `artifacts/parser_cross_arch_repro_matrix/<timestamp>/events.jsonl`
- `artifacts/parser_cross_arch_repro_matrix/<timestamp>/commands.txt`
- `artifacts/parser_cross_arch_repro_matrix/<timestamp>/matrix_lane_deltas.jsonl`
- `artifacts/parser_cross_arch_repro_matrix/<timestamp>/matrix_summary.json`

## Parser Third-Party Rerun Kit Gate

`bd-2mds.1.7.3` packages cross-architecture matrix evidence into a deterministic
third-party rerun bundle and fails closed unless
`matrix_input_status == ready_for_external_rerun`, including fail-closed
behavior when `rch` local fallback or missing remote-exit markers are detected.
The gate also fails closed if `rch` reports a wrapped `timeout_secs` value
below the requested `RCH_BUILD_TIMEOUT_*` value so timeout-policy drift is
captured as blocker evidence.

```bash
# third-party rerun kit contract/test gate (rch-backed check + test + clippy)
./scripts/run_parser_third_party_rerun_kit.sh ci

# package-mode run with explicit PSRP-07.2 matrix inputs
PARSER_RERUN_KIT_MATRIX_SUMMARY=artifacts/.../matrix_summary.json \
PARSER_RERUN_KIT_MATRIX_DELTAS=artifacts/.../matrix_lane_deltas.jsonl \
PARSER_RERUN_KIT_MATRIX_MANIFEST=artifacts/.../run_manifest.json \
./scripts/run_parser_third_party_rerun_kit.sh package

# one-command replay wrapper
./scripts/e2e/parser_third_party_rerun_kit_replay.sh
```

Contract and vectors:

- [`docs/PARSER_THIRD_PARTY_RERUN_KIT.md`](./docs/PARSER_THIRD_PARTY_RERUN_KIT.md)
- `crates/franken-engine/tests/fixtures/parser_third_party_rerun_kit_v1.json`
- `crates/franken-engine/tests/parser_third_party_rerun_kit.rs`

Artifacts are written under:

- `artifacts/parser_third_party_rerun_kit/<timestamp>/run_manifest.json`
- `artifacts/parser_third_party_rerun_kit/<timestamp>/events.jsonl`
- `artifacts/parser_third_party_rerun_kit/<timestamp>/commands.txt`
- `artifacts/parser_third_party_rerun_kit/<timestamp>/step_logs/step_*.log`
- `artifacts/parser_third_party_rerun_kit/<timestamp>/rerun_kit_index.json`
- `artifacts/parser_third_party_rerun_kit/<timestamp>/verifier_notes.md`

## Parser Correctness Promotion Gate

`bd-2mds.1.8.2` enforces fail-closed promotion policy for unresolved
high-severity drift and non-green correctness evidence lanes.
The gate runner also fails closed on `rch` local-fallback and artifact-retrieval
failure signatures.

```bash
# parser correctness promotion gate (rch-backed check + test + clippy)
./scripts/run_parser_correctness_promotion_gate.sh ci

# one-command replay wrapper
./scripts/e2e/parser_correctness_promotion_gate_replay.sh
```

Contract and vectors:

- [`docs/PARSER_CORRECTNESS_PROMOTION_GATE.md`](./docs/PARSER_CORRECTNESS_PROMOTION_GATE.md)
- `crates/franken-engine/tests/fixtures/parser_correctness_promotion_gate_v1.json`
- `crates/franken-engine/tests/parser_correctness_promotion_gate.rs`

Artifacts are written under:

- `artifacts/parser_correctness_promotion_gate/<timestamp>/run_manifest.json`
- `artifacts/parser_correctness_promotion_gate/<timestamp>/events.jsonl`
- `artifacts/parser_correctness_promotion_gate/<timestamp>/commands.txt`

## Parser Performance Promotion Gate

`bd-2mds.1.8.3` enforces fail-closed promotion policy for parser performance
wins against required peers/quantiles with confidence-bounded and reproducible
evidence.

```bash
# parser performance promotion gate (rch-backed check + test + clippy)
./scripts/run_parser_performance_promotion_gate.sh ci

# one-command replay wrapper
./scripts/e2e/parser_performance_promotion_gate_replay.sh
```

Contract and vectors:

- [`docs/PARSER_PERFORMANCE_PROMOTION_GATE.md`](./docs/PARSER_PERFORMANCE_PROMOTION_GATE.md)
- `crates/franken-engine/tests/fixtures/parser_performance_promotion_gate_v1.json`
- `crates/franken-engine/tests/parser_performance_promotion_gate.rs`

Artifacts are written under:

- `artifacts/parser_performance_promotion_gate/<timestamp>/run_manifest.json`
- `artifacts/parser_performance_promotion_gate/<timestamp>/events.jsonl`
- `artifacts/parser_performance_promotion_gate/<timestamp>/commands.txt`

## Parser API Compatibility Gate

`bd-2mds.1.10.3` stabilizes public parser API contracts and integration
ergonomics with deterministic compatibility vectors + migration policy checks.

```bash
# parser API compatibility gate (rch-backed check + compatibility vectors + clippy)
./scripts/run_parser_api_compatibility_gate.sh ci
```

Contract and vectors:

- [`docs/PARSER_API_COMPATIBILITY_CONTRACT.md`](./docs/PARSER_API_COMPATIBILITY_CONTRACT.md)
- `crates/franken-engine/tests/fixtures/parser_api_compatibility_contract_v1.json`
- `crates/franken-engine/tests/parser_api_compatibility_contract.rs`

Artifacts are written under:

- `artifacts/parser_api_compatibility/<timestamp>/run_manifest.json`
- `artifacts/parser_api_compatibility/<timestamp>/events.jsonl`
- `artifacts/parser_api_compatibility/<timestamp>/commands.txt`

## Parser Operator/Developer Runbook Gate

`bd-2mds.1.10.4` adds replay-first troubleshooting runbooks and deterministic
operator drills for parser diagnostics/recovery/API/user-impact incidents.

```bash
# parser operator/developer runbook gate (rch-backed check + test + clippy)
./scripts/run_parser_operator_developer_runbook.sh ci

# run scriptable drill mode (includes replay-path validation)
./scripts/run_parser_operator_developer_runbook.sh drill

# one-command replay wrapper
./scripts/e2e/parser_operator_developer_runbook_replay.sh
```

Contract and vectors:

- [`docs/PARSER_OPERATOR_DEVELOPER_RUNBOOK.md`](./docs/PARSER_OPERATOR_DEVELOPER_RUNBOOK.md)
- `crates/franken-engine/tests/fixtures/parser_operator_developer_runbook_v1.json`
- `crates/franken-engine/tests/parser_operator_developer_runbook.rs`

Artifacts are written under:

- `artifacts/parser_operator_developer_runbook/<timestamp>/run_manifest.json`
- `artifacts/parser_operator_developer_runbook/<timestamp>/events.jsonl`
- `artifacts/parser_operator_developer_runbook/<timestamp>/commands.txt`

## Parser Differential Nightly Governance Gate

`bd-2mds.1.2.4.2` defines nightly differential scheduling, waiver-aware severity
governance, and deterministic remediation bead promotion/update actions.

```bash
# parser differential nightly governance gate (rch-backed check + test + clippy)
./scripts/run_parser_differential_nightly_governance.sh ci
```

Contract and vectors:

- [`docs/PARSER_DIFFERENTIAL_NIGHTLY_GOVERNANCE.md`](./docs/PARSER_DIFFERENTIAL_NIGHTLY_GOVERNANCE.md)
- `crates/franken-engine/tests/fixtures/parser_differential_nightly_governance_v1.json`
- `crates/franken-engine/tests/parser_differential_nightly_governance.rs`

Deterministic replay wrapper:

```bash
./scripts/e2e/parser_differential_nightly_governance_replay.sh
```

Artifacts are written under:

- `artifacts/parser_differential_nightly_governance/<timestamp>/run_manifest.json`
- `artifacts/parser_differential_nightly_governance/<timestamp>/events.jsonl`
- `artifacts/parser_differential_nightly_governance/<timestamp>/commands.txt`

## Parser Regression Bisector Scoreboard Gate

`bd-2mds.1.6.4` automates parser regression attribution and deterministic
scoreboard publication across telemetry history snapshots.

```bash
# parser regression bisector scoreboard gate (rch-backed check + test + clippy)
./scripts/run_parser_regression_bisector_scoreboard.sh ci
```

Contract and vectors:

- [`docs/PARSER_REGRESSION_BISECTOR_SCOREBOARD.md`](./docs/PARSER_REGRESSION_BISECTOR_SCOREBOARD.md)
- `crates/franken-engine/tests/fixtures/parser_regression_bisector_scoreboard_v1.json`
- `crates/franken-engine/tests/parser_regression_bisector_scoreboard.rs`

Deterministic replay wrapper:

```bash
./scripts/e2e/parser_regression_bisector_scoreboard_replay.sh
```

Artifacts are written under:

- `artifacts/parser_regression_bisector_scoreboard/<timestamp>/run_manifest.json`
- `artifacts/parser_regression_bisector_scoreboard/<timestamp>/events.jsonl`
- `artifacts/parser_regression_bisector_scoreboard/<timestamp>/commands.txt`

## Observability Information-Theoretic Gate

`bd-mjh3.17` defines FRX-17 observability channel governance and compression
contracts, including deterministic probe selection and fail-closed quality
demotion semantics.

```bash
# FRX-17 observability gate (rch-backed check + integration tests + clippy)
./scripts/run_observability_information_theoretic_gate.sh ci
```

Contract and integration surface:

- [`docs/OBSERVABILITY_INFORMATION_THEORETIC_CHANNEL.md`](./docs/OBSERVABILITY_INFORMATION_THEORETIC_CHANNEL.md)
- `crates/franken-engine/tests/observability_channel_model.rs`

Artifacts are written under:

- `artifacts/observability_information_theoretic/<timestamp>/run_manifest.json`
- `artifacts/observability_information_theoretic/<timestamp>/events.jsonl`
- `artifacts/observability_information_theoretic/<timestamp>/commands.txt`

## FRX Compiler Lane Charter Gate

`bd-mjh3.10.2` ships a deterministic gate for compiler-lane charter contract
validation and evidence emission.

```bash
# FRX compiler lane charter gate (rch-backed check + test + clippy)
./scripts/run_frx_compiler_lane_charter_suite.sh ci
```

Deterministic replay wrapper:

```bash
./scripts/e2e/frx_compiler_lane_charter_replay.sh
```

Artifacts are written under:

- `artifacts/frx_compiler_lane_charter/<timestamp>/run_manifest.json`
- `artifacts/frx_compiler_lane_charter/<timestamp>/events.jsonl`
- `artifacts/frx_compiler_lane_charter/<timestamp>/commands.txt`

## FRX Verification Lane Charter Gate

`bd-mjh3.10.4` ships a deterministic gate for verification/formal lane charter
contract validation and evidence emission.

```bash
# FRX verification lane charter gate (rch-backed check + test + clippy)
./scripts/run_frx_verification_lane_charter_suite.sh ci
```

Deterministic replay wrapper:

```bash
./scripts/e2e/frx_verification_lane_charter_replay.sh
```

Artifacts are written under:

- `artifacts/frx_verification_lane_charter/<timestamp>/run_manifest.json`
- `artifacts/frx_verification_lane_charter/<timestamp>/events.jsonl`
- `artifacts/frx_verification_lane_charter/<timestamp>/commands.txt`

## FRX React Lockstep Differential Oracle Gate

`bd-mjh3.5.1` ships a deterministic React-vs-FrankenReact lockstep oracle with
fixture-linked divergence classification and replay commands.

```bash
# FRX React lockstep oracle gate (rch-backed check + tests + clippy + oracle run)
./scripts/run_frx_lockstep_oracle_suite.sh ci
```

Deterministic replay wrapper:

```bash
./scripts/e2e/frx_lockstep_oracle_replay.sh
```

Contract and vectors:

- `crates/franken-engine/src/frx_lockstep_oracle.rs`
- `crates/franken-engine/src/bin/frx_lockstep_oracle.rs`
- `crates/franken-engine/tests/frx_lockstep_oracle.rs`

Artifacts are written under:

- `artifacts/frx_lockstep_oracle/<timestamp>/run_manifest.json`
- `artifacts/frx_lockstep_oracle/<timestamp>/events.jsonl`
- `artifacts/frx_lockstep_oracle/<timestamp>/commands.txt`
- `artifacts/frx_lockstep_oracle/<timestamp>/oracle_report.json`

## FRX Optimization Lane Charter Gate

`bd-mjh3.10.5` ships a deterministic gate for optimization/performance lane
charter contract validation and evidence emission.

```bash
# FRX optimization lane charter gate (rch-backed check + test + clippy)
./scripts/run_frx_optimization_lane_charter_suite.sh ci
```

Deterministic replay wrapper:

```bash
./scripts/e2e/frx_optimization_lane_charter_replay.sh
```

Artifacts are written under:

- `artifacts/frx_optimization_lane_charter/<timestamp>/run_manifest.json`
- `artifacts/frx_optimization_lane_charter/<timestamp>/events.jsonl`
- `artifacts/frx_optimization_lane_charter/<timestamp>/commands.txt`

## Compiler Hotspot Optimization Campaign Gate

`bd-mjh3.6.2` ships a deterministic compiler hotspot campaign gate for
one-lever optimization ranking across analysis-graph construction, lowering
throughput, optimization-pass cost, and codegen size/latency signals.

```bash
# compiler hotspot optimization campaign gate (rch-backed check + test + clippy)
./scripts/run_compiler_hotspot_optimization_campaign.sh ci
```

Deterministic replay wrapper:

```bash
./scripts/e2e/compiler_hotspot_optimization_campaign_replay.sh
```

Artifacts are written under:

- `artifacts/compiler_hotspot_optimization_campaign/<timestamp>/run_manifest.json`
- `artifacts/compiler_hotspot_optimization_campaign/<timestamp>/events.jsonl`
- `artifacts/compiler_hotspot_optimization_campaign/<timestamp>/commands.txt`

## FRX Toolchain Lane Charter Gate

`bd-mjh3.10.6` ships a deterministic gate for toolchain/ecosystem lane charter
contract validation and evidence emission.

```bash
# FRX toolchain lane charter gate (rch-backed check + test + clippy)
./scripts/run_frx_toolchain_lane_charter_suite.sh ci
```

Deterministic replay wrapper:

```bash
./scripts/e2e/frx_toolchain_lane_charter_replay.sh
```

Artifacts are written under:

- `artifacts/frx_toolchain_lane_charter/<timestamp>/run_manifest.json`
- `artifacts/frx_toolchain_lane_charter/<timestamp>/events.jsonl`
- `artifacts/frx_toolchain_lane_charter/<timestamp>/commands.txt`

## FRX Governance/Evidence Lane Charter Gate

`bd-mjh3.10.7` ships a deterministic gate for governance/evidence lane charter
contract validation and evidence emission.

```bash
# FRX governance/evidence lane charter gate (rch-backed check + test + clippy)
./scripts/run_frx_governance_evidence_lane_charter_suite.sh ci
```

Deterministic replay wrapper:

```bash
./scripts/e2e/frx_governance_evidence_lane_charter_replay.sh
```

Artifacts are written under:

- `artifacts/frx_governance_evidence_lane_charter/<timestamp>/run_manifest.json`
- `artifacts/frx_governance_evidence_lane_charter/<timestamp>/events.jsonl`
- `artifacts/frx_governance_evidence_lane_charter/<timestamp>/commands.txt`

## FRX Adoption/Release Lane Charter Gate

`bd-mjh3.10.8` ships a deterministic gate for adoption/release lane charter
contract validation and evidence emission.

```bash
# FRX adoption/release lane charter gate (rch-backed check + test + clippy)
./scripts/run_frx_adoption_release_lane_charter_suite.sh ci
```

Deterministic replay wrapper:

```bash
./scripts/e2e/frx_adoption_release_lane_charter_replay.sh
```

Artifacts are written under:

- `artifacts/frx_adoption_release_lane_charter/<timestamp>/run_manifest.json`
- `artifacts/frx_adoption_release_lane_charter/<timestamp>/events.jsonl`
- `artifacts/frx_adoption_release_lane_charter/<timestamp>/commands.txt`

## FRX Local Semantic Atlas Gate

`bd-mjh3.14.1` ships a deterministic gate for local semantic atlas contracts,
fixture/trace linkage, and blocking quality-debt enforcement.

```bash
# FRX local semantic atlas gate (rch-backed check + test + clippy)
./scripts/run_frx_local_semantic_atlas_suite.sh ci
```

Deterministic replay wrapper:

```bash
./scripts/e2e/frx_local_semantic_atlas_replay.sh
```

Artifacts are written under:

- `artifacts/frx_local_semantic_atlas/<timestamp>/run_manifest.json`
- `artifacts/frx_local_semantic_atlas/<timestamp>/events.jsonl`
- `artifacts/frx_local_semantic_atlas/<timestamp>/commands.txt`

## FRX Track D WASM Lane + Hybrid Router Sprint Gate

`bd-mjh3.11.4` ships a deterministic gate for Track D WASM lane + hybrid router
sprint contract validation and evidence emission.

```bash
# FRX Track D WASM lane + hybrid router sprint gate (rch-backed check + test + clippy)
./scripts/run_frx_track_d_wasm_lane_hybrid_router_sprint_suite.sh ci
```

Deterministic replay wrapper:

```bash
./scripts/e2e/frx_track_d_wasm_lane_hybrid_router_sprint_replay.sh
```

Artifacts are written under:

- `artifacts/frx_track_d_wasm_lane_hybrid_router_sprint/<timestamp>/run_manifest.json`
- `artifacts/frx_track_d_wasm_lane_hybrid_router_sprint/<timestamp>/events.jsonl`
- `artifacts/frx_track_d_wasm_lane_hybrid_router_sprint/<timestamp>/commands.txt`

## FRX Track E Verification/Fuzz/Formal Coverage Sprint Gate

`bd-mjh3.11.5` ships a deterministic gate for Track E verification/fuzz/formal
coverage sprint contract validation and evidence emission.

```bash
# FRX Track E verification/fuzz/formal coverage sprint gate (rch-backed check + test + clippy)
./scripts/run_frx_track_e_verification_fuzz_formal_coverage_sprint_suite.sh ci
```

Deterministic replay wrapper:

```bash
./scripts/e2e/frx_track_e_verification_fuzz_formal_coverage_sprint_replay.sh
```

Artifacts are written under:

- `artifacts/frx_track_e_verification_fuzz_formal_coverage_sprint/<timestamp>/run_manifest.json`
- `artifacts/frx_track_e_verification_fuzz_formal_coverage_sprint/<timestamp>/events.jsonl`
- `artifacts/frx_track_e_verification_fuzz_formal_coverage_sprint/<timestamp>/commands.txt`

## FRX Ecosystem Compatibility Matrix Gate

`bd-mjh3.7.3` ships a deterministic gate for ecosystem compatibility matrix
validation across high-impact React stacks (state/routing/forms/data) and
legacy API surfaces.

```bash
# FRX ecosystem compatibility matrix gate (rch-backed check + test + clippy)
./scripts/run_frx_ecosystem_compatibility_matrix_suite.sh ci
```

Deterministic replay wrapper:

```bash
./scripts/e2e/frx_ecosystem_compatibility_matrix_replay.sh ci
```

Artifacts are written under:

- `artifacts/frx_ecosystem_compatibility_matrix/<timestamp>/run_manifest.json`
- `artifacts/frx_ecosystem_compatibility_matrix/<timestamp>/events.jsonl`
- `artifacts/frx_ecosystem_compatibility_matrix/<timestamp>/commands.txt`

## FRX SSR/Hydration/RSC Compatibility Strategy Gate

`bd-mjh3.7.2` ships a deterministic gate for server-render contracts, hydration
boundary equivalence, suspense streaming handoff behavior, and explicit RSC
fallback routing when guarantees cannot be upheld.

```bash
# FRX SSR/hydration/RSC compatibility strategy gate (rch-backed check + test + clippy)
./scripts/run_frx_ssr_hydration_rsc_compatibility_strategy_suite.sh ci
```

Deterministic replay wrapper:

```bash
./scripts/e2e/frx_ssr_hydration_rsc_compatibility_strategy_replay.sh ci
```

Artifacts are written under:

- `artifacts/frx_ssr_hydration_rsc_compatibility_strategy/<timestamp>/run_manifest.json`
- `artifacts/frx_ssr_hydration_rsc_compatibility_strategy/<timestamp>/events.jsonl`
- `artifacts/frx_ssr_hydration_rsc_compatibility_strategy/<timestamp>/commands.txt`

## FRX Incremental Adoption Controls Gate

`bd-mjh3.7.4` ships a deterministic gate for incremental opt-in controls,
policy-based opt-out/force-fallback toggles, canary/rollback flow validation,
and actionable migration diagnostics.

```bash
# FRX incremental adoption controls gate (rch-backed check + test + clippy)
./scripts/run_frx_incremental_adoption_controls_suite.sh ci
```

Deterministic replay wrapper:

```bash
./scripts/e2e/frx_incremental_adoption_controls_replay.sh ci
```

Artifacts are written under:

- `artifacts/frx_incremental_adoption_controls/<timestamp>/run_manifest.json`
- `artifacts/frx_incremental_adoption_controls/<timestamp>/events.jsonl`
- `artifacts/frx_incremental_adoption_controls/<timestamp>/commands.txt`

## FRX Pilot App Program and A/B Rollout Harness Gate

`bd-mjh3.9.1` ships a deterministic gate for pilot portfolio stratification,
A/B plus shadow-run telemetry capture, off-policy estimator requirements
(IPS/DR), sequential-valid stop/promote/rollback decision policy, and
incident-to-replay/evidence linkage.

```bash
# FRX pilot rollout harness gate (rch-backed check + test + clippy)
./scripts/run_frx_pilot_rollout_harness_suite.sh ci
```

Deterministic replay wrapper:

```bash
./scripts/e2e/frx_pilot_rollout_harness_replay.sh ci
```

Artifacts are written under:

- `artifacts/frx_pilot_rollout_harness/<timestamp>/run_manifest.json`
- `artifacts/frx_pilot_rollout_harness/<timestamp>/events.jsonl`
- `artifacts/frx_pilot_rollout_harness/<timestamp>/commands.txt`

## FRX Online Regret + Change-Point Demotion Controller Gate

`bd-mjh3.15.3` ships a deterministic gate for online regret/change-point
monitoring, fail-closed demotion policy enforcement, and replay-stable
structured evidence linkage.

```bash
# FRX online regret + change-point demotion controller gate (rch-backed check + test + clippy)
./scripts/run_frx_online_regret_change_point_demotion_controller_suite.sh ci
```

Deterministic replay wrapper:

```bash
./scripts/e2e/frx_online_regret_change_point_demotion_controller_replay.sh ci
```

Artifacts are written under:

- `artifacts/frx_online_regret_change_point_demotion_controller/<timestamp>/run_manifest.json`
- `artifacts/frx_online_regret_change_point_demotion_controller/<timestamp>/events.jsonl`
- `artifacts/frx_online_regret_change_point_demotion_controller/<timestamp>/commands.txt`

## RGC Verification Coverage Matrix Gate

`bd-1lsy.11.1` ships a deterministic gate for the RGC verification coverage
matrix contract (`unit`/`integration`/`e2e` row mapping, required log fields,
artifact triad, and live `bd-1lsy*` snapshot parity checks).

```bash
# RGC verification coverage matrix gate (rch-backed check + test + clippy)
./scripts/run_rgc_verification_coverage_matrix.sh ci
```

Deterministic replay wrapper:

```bash
./scripts/e2e/rgc_verification_coverage_matrix_replay.sh ci
```

Contract and vectors:

- [`docs/RGC_VERIFICATION_COVERAGE_MATRIX_V1.md`](./docs/RGC_VERIFICATION_COVERAGE_MATRIX_V1.md)
- `docs/rgc_verification_coverage_matrix_v1.json`
- `crates/franken-engine/tests/rgc_verification_coverage_matrix.rs`

Artifacts are written under:

- `artifacts/rgc_verification_coverage_matrix/<timestamp>/run_manifest.json`
- `artifacts/rgc_verification_coverage_matrix/<timestamp>/events.jsonl`
- `artifacts/rgc_verification_coverage_matrix/<timestamp>/commands.txt`

## Phase-A Exit Gate

`bd-1csl.1` adds a deterministic Phase-A gate runner that checks critical
dependency-bead closure and aggregates parser/test262 gate evidence into a
single manifest.

```bash
# Default behavior: fail fast when dependencies are unresolved
./scripts/run_phase_a_exit_gate.sh check

# Full gate orchestration (delegates heavy cargo work through existing rch-backed scripts)
./scripts/run_phase_a_exit_gate.sh ci

# Force sub-gate evidence collection even while dependencies are unresolved
PHASE_A_GATE_RUN_SUBGATES_WHEN_BLOCKED=1 ./scripts/run_phase_a_exit_gate.sh check

# Dependency-only check (explicitly skip sub-gates)
PHASE_A_GATE_SKIP_SUBGATES=1 ./scripts/run_phase_a_exit_gate.sh check
```

Phase-A gate artifacts are written under
`artifacts/phase_a_exit_gate/<timestamp>/`.

## RGC Deterministic Test Harness Utilities Gate

`bd-1lsy.11.2` adds reusable deterministic test-harness utilities for fixture
loading, stable seed/context wiring, and artifact-triad emission across runtime,
parser, and security verification lanes.

```bash
# RGC test-harness utility gate (rch-backed check + test + clippy)
./scripts/run_rgc_test_harness_suite.sh ci

# deterministic replay wrapper
./scripts/e2e/rgc_test_harness_replay.sh ci
```

`run_rgc_test_harness_suite.sh` defaults `CARGO_TARGET_DIR` to
`/data/projects/franken_engine/target_rch_rgc_test_harness` so rch workers can
reuse incremental artifacts across runs. Override with `CARGO_TARGET_DIR=...`
if you need lane-specific isolation.

Artifacts are written under:

- `artifacts/rgc_test_harness/<timestamp>/run_manifest.json`
- `artifacts/rgc_test_harness/<timestamp>/events.jsonl`
- `artifacts/rgc_test_harness/<timestamp>/commands.txt`
- `artifacts/rgc_test_harness/<timestamp>/rch-log.*` (per-step rch execution logs)

## RGC Fault-Injection and Chaos Verification Pack

`bd-1lsy.11.6` adds deterministic fault-injection/chaos verification for
containment triggers, degraded-mode behavior, and recovery correctness.

```bash
# RGC fault-injection/chaos verification pack gate (rch-backed check + test + clippy)
./scripts/run_rgc_fault_injection_chaos_verification_pack.sh ci

# deterministic replay wrapper
./scripts/e2e/rgc_fault_injection_chaos_verification_pack_replay.sh ci
```

Contract and vectors:

- [`docs/RGC_FAULT_INJECTION_CHAOS_VERIFICATION_PACK_V1.md`](./docs/RGC_FAULT_INJECTION_CHAOS_VERIFICATION_PACK_V1.md)
- `docs/rgc_fault_injection_chaos_verification_pack_v1.json`
- `docs/rgc_fault_injection_chaos_verification_vectors_v1.json`
- `crates/franken-engine/tests/rgc_fault_injection_chaos_verification_pack.rs`

Artifacts are written under:

- `artifacts/rgc_fault_injection_chaos_verification_pack/<timestamp>/run_manifest.json`
- `artifacts/rgc_fault_injection_chaos_verification_pack/<timestamp>/events.jsonl`
- `artifacts/rgc_fault_injection_chaos_verification_pack/<timestamp>/commands.txt`
- `artifacts/rgc_fault_injection_chaos_verification_pack/<timestamp>/chaos_verification_report.json`
- `artifacts/rgc_fault_injection_chaos_verification_pack/<timestamp>/step_logs/step_*.log`

## RGC Runtime Semantics Verification Pack

`bd-1lsy.11.7` adds deterministic runtime-semantics verification coverage for
arithmetic/control-flow behavior, object+closure interactions, and async
error-path replay stability.

```bash
# RGC runtime-semantics verification pack gate (rch-backed check + test + clippy)
./scripts/run_rgc_runtime_semantics_verification_pack.sh ci

# deterministic replay wrapper
./scripts/e2e/rgc_runtime_semantics_verification_pack_replay.sh ci
```

Contract and vectors:

- [`docs/RGC_RUNTIME_SEMANTICS_VERIFICATION_PACK_V1.md`](./docs/RGC_RUNTIME_SEMANTICS_VERIFICATION_PACK_V1.md)
- `docs/rgc_runtime_semantics_verification_pack_v1.json`
- `docs/rgc_runtime_semantics_verification_vectors_v1.json`
- `crates/franken-engine/tests/rgc_runtime_semantics_verification_pack.rs`

Artifacts are written under:

- `artifacts/rgc_runtime_semantics_verification_pack/<timestamp>/run_manifest.json`
- `artifacts/rgc_runtime_semantics_verification_pack/<timestamp>/events.jsonl`
- `artifacts/rgc_runtime_semantics_verification_pack/<timestamp>/commands.txt`
- `artifacts/rgc_runtime_semantics_verification_pack/<timestamp>/runtime_semantics_verification_report.json`
- `artifacts/rgc_runtime_semantics_verification_pack/<timestamp>/step_logs/step_*.log`

## RGC Exception and Diagnostic Semantics Gate

`bd-1lsy.4.5` adds a deterministic exception/diagnostics gate for runtime
boundary propagation (`sync_callframe` / `async_job` / `hostcall`), machine-stable
error metadata, and lane-differential classification with explicit remediation
guidance for intentional metadata-only divergences.

```bash
# RGC exception/diagnostics semantics gate (rch-backed check + test + clippy)
./scripts/run_rgc_exception_diagnostics_semantics.sh ci

# deterministic replay wrapper
./scripts/e2e/rgc_exception_diagnostics_semantics_replay.sh ci
```

Contract and vectors:

- [`docs/RGC_EXCEPTION_DIAGNOSTICS_SEMANTICS_V1.md`](./docs/RGC_EXCEPTION_DIAGNOSTICS_SEMANTICS_V1.md)
- `docs/rgc_exception_diagnostics_semantics_v1.json`
- `docs/rgc_exception_diagnostics_semantics_vectors_v1.json`
- `crates/franken-engine/tests/rgc_exception_diagnostics_semantics.rs`

Artifacts are written under:

- `artifacts/rgc_exception_diagnostics_semantics/<timestamp>/run_manifest.json`
- `artifacts/rgc_exception_diagnostics_semantics/<timestamp>/events.jsonl`
- `artifacts/rgc_exception_diagnostics_semantics/<timestamp>/commands.txt`
- `artifacts/rgc_exception_diagnostics_semantics/<timestamp>/diagnostic_trace.json`
- `artifacts/rgc_exception_diagnostics_semantics/<timestamp>/step_logs/step_*.log`

## RGC Performance and Regression Verification Pack

`bd-1lsy.11.10` adds deterministic performance/regression verification for
benchmark integrity + profiler correctness, with fail-closed publication gating
when baseline/significance/receipt integrity checks fail.

```bash
# RGC performance/regression verification pack gate (rch-backed check + test + clippy)
./scripts/run_rgc_performance_regression_verification_pack.sh ci

# deterministic replay wrapper
./scripts/e2e/rgc_performance_regression_verification_pack_replay.sh ci
```

Contract and vectors:

- [`docs/RGC_PERFORMANCE_REGRESSION_VERIFICATION_PACK_V1.md`](./docs/RGC_PERFORMANCE_REGRESSION_VERIFICATION_PACK_V1.md)
- `docs/rgc_performance_regression_verification_pack_v1.json`
- `crates/franken-engine/tests/rgc_performance_regression_verification_pack.rs`

Artifacts are written under:

- `artifacts/rgc_performance_regression_verification_pack/<timestamp>/run_manifest.json`
- `artifacts/rgc_performance_regression_verification_pack/<timestamp>/events.jsonl`
- `artifacts/rgc_performance_regression_verification_pack/<timestamp>/commands.txt`

## RGC Statistical Validation Pipeline

`bd-1lsy.8.2` adds deterministic variance/significance/effect-size validation
for benchmark promotion decisions, with fail-closed quarantine semantics for
high-variance or low-confidence runs.

```bash
# RGC statistical validation pipeline gate (rch-backed check + test + clippy)
./scripts/run_rgc_statistical_validation_pipeline.sh ci

# deterministic replay wrapper
./scripts/e2e/rgc_statistical_validation_pipeline_replay.sh ci
```

Contract and vectors:

- [`docs/RGC_STATISTICAL_VALIDATION_PIPELINE_V1.md`](./docs/RGC_STATISTICAL_VALIDATION_PIPELINE_V1.md)
- `docs/rgc_statistical_validation_pipeline_v1.json`
- `crates/franken-engine/tests/rgc_statistical_validation_pipeline.rs`

Artifacts are written under:

- `artifacts/rgc_statistical_validation_pipeline/<timestamp>/run_manifest.json`
- `artifacts/rgc_statistical_validation_pipeline/<timestamp>/events.jsonl`
- `artifacts/rgc_statistical_validation_pipeline/<timestamp>/commands.txt`
- `artifacts/rgc_statistical_validation_pipeline/<timestamp>/support_bundle/stats_verdict_report.json`

## RGC Performance Regression Gate

`bd-1lsy.8.3` adds deterministic regression verdicting with culprit ranking and
waiver-expiry fail-closed enforcement for promotion decisions.

```bash
# RGC performance regression gate (rch-backed check + test + clippy)
./scripts/run_rgc_performance_regression_gate.sh ci

# deterministic replay wrapper
./scripts/e2e/rgc_performance_regression_gate_replay.sh ci
```

Contract and vectors:

- [`docs/RGC_PERFORMANCE_REGRESSION_GATE_V1.md`](./docs/RGC_PERFORMANCE_REGRESSION_GATE_V1.md)
- `docs/rgc_performance_regression_gate_v1.json`
- `crates/franken-engine/tests/rgc_performance_regression_gate.rs`

Artifacts are written under:

- `artifacts/rgc_performance_regression_gate/<timestamp>/run_manifest.json`
- `artifacts/rgc_performance_regression_gate/<timestamp>/events.jsonl`
- `artifacts/rgc_performance_regression_gate/<timestamp>/commands.txt`
- `artifacts/rgc_performance_regression_gate/<timestamp>/regression_report.json`

## RGC CLI and Operator Workflow Verification Pack

`bd-1lsy.11.11` adds deterministic verification for operator CLI workflows
covering both golden-path and failure-path onboarding/triage scenarios.

```bash
# RGC CLI/operator workflow verification pack gate (rch-backed check + test + clippy)
./scripts/run_rgc_cli_operator_workflow_verification_pack.sh ci

# deterministic replay wrapper
./scripts/e2e/rgc_cli_operator_workflow_verification_pack_replay.sh ci
```

Contract and vectors:

- [`docs/RGC_CLI_OPERATOR_WORKFLOW_VERIFICATION_PACK_V1.md`](./docs/RGC_CLI_OPERATOR_WORKFLOW_VERIFICATION_PACK_V1.md)
- `docs/rgc_cli_operator_workflow_verification_pack_v1.json`
- `crates/franken-engine/tests/rgc_cli_operator_workflow_verification_pack.rs`

Artifacts are written under:

- `artifacts/rgc_cli_operator_workflow_verification_pack/<timestamp>/run_manifest.json`
- `artifacts/rgc_cli_operator_workflow_verification_pack/<timestamp>/events.jsonl`
- `artifacts/rgc_cli_operator_workflow_verification_pack/<timestamp>/commands.txt`

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| Compile artifact verification fails | Source path, parse goal, or artifact contents are stale/mismatched | Rerun `frankenctl compile --input <source.js> --out <artifact.json> --goal <script|module>` and then `frankenctl verify compile-artifact --input <artifact.json>` |
| `doctor` summary reports missing readiness signals | Runtime diagnostics input or optional signal bundles are incomplete | Rebuild the JSON input bundle and rerun `frankenctl doctor --input <runtime_input.json> --summary --out-dir <dir>` |
| Replay mismatch on a captured trace | Snapshot or nondeterminism transcript is incomplete | Rerun `frankenctl replay run --trace <trace.json> --mode validate --out <report.json>` and inspect the replay report |
| Receipt verification failure | Verifier input is stale or the receipt ID does not match the bundle | Run `frankenctl verify receipt --input <verifier_input.json> --receipt-id <id> --summary` and inspect the rendered verdict |
| Benchmark publication gate fails | Claim bundle or publication input is incomplete, stale, or below the scoring threshold | Run `frankenctl benchmark verify --bundle <dir> --summary --output <report.json>` and `frankenctl benchmark score --input <publication_gate_input.json> --output <results.json>` |

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
