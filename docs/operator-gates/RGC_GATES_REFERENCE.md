# RGC Gates Reference

This document contains comprehensive reference material for all RGC (Release Gate Contract) scripts, 
artifact paths, and replay commands. This content was moved from README.md to provide operators 
with detailed gate documentation while keeping the main README focused on getting started.

For a quick overview, see the main [README.md](../../README.md).

---

## RGC Signed Decision Receipt Gate (FE-CLAIM-004)

`bd-cixqu.1.4` defines the canonical gate for FE-CLAIM-004 (cryptographic
decision receipts + transparency log + TEE attestation). The `ci` mode
cross-references every FE-CLAIM-004 sub-claim to its in-tree proof surface and
content-addresses each artifact (sha256), failing closed if any required file
is missing or if any sub-claim (A.1/A.2/A.3) has zero present artifacts:

- **A.1** receipt-only proof handle — `proof_schema.rs` (`OptReceipt`),
  `receipt_verifier_pipeline.rs`, `evidence_contract.rs`, and the receipt tests.
- **A.2** transparency log — `transparency_log.rs`, `mmr_proof.rs`
  (Merkle inclusion + consistency proofs).
- **A.3** TEE attestation — `tee_attestation_policy.rs`, `tee_live_quote.rs`.

Like the other RGC reality-check gates, `ci` does **not** invoke cargo; the
in-tree test is run separately via rch.

```bash
# FE-CLAIM-004 signed-decision-receipt gate
./scripts/run_rgc_signed_decision_receipt.sh ci

# shape-only self-check (no filesystem mutation beyond the run dir)
./scripts/run_rgc_signed_decision_receipt.sh selftest

# deterministic replay wrapper — auto-detects the latest complete bundle,
# or honours RGC_SIGNED_DECISION_RECEIPT_REPLAY_RUN_DIR=<dir>; fails closed
# (exit 1) if no complete bundle exists.
./scripts/e2e/rgc_signed_decision_receipt_replay.sh ci

# in-tree cargo companion (run via rch)
cargo test --test rgc_signed_decision_receipt
```

Test companion and surface:

- `crates/franken-engine/tests/rgc_signed_decision_receipt.rs`
- `crates/franken-engine/src/proof_schema.rs`
- `crates/franken-engine/src/receipt_verifier_pipeline.rs`
- `crates/franken-engine/src/transparency_log.rs`
- `crates/franken-engine/src/tee_attestation_policy.rs`

Artifacts are written under `artifacts/signed_decision_receipt/<timestamp>/`:

- `run_manifest.json` — verdict + content-addressed required-surface set
- `events.jsonl` — one event per cross-referenced artifact + per-sub-claim rollup
- `commands.txt` — rerun command transcript
- `trace_ids.json` — canonical trace/decision/policy ids + per-step trace ids
- `step_logs/` — one log file per cross-reference step

Replay comparison (exit codes): `0` verdict + surface match · `1` no complete
source bundle · `2` invalid bundle / no replay manifest · `3` verdict mismatch ·
`4` required-surface (content-address) mismatch.

### Receipt verification & incident triage (A.7)

`bd-cixqu.1.7` adds the operator-facing surface for verifying an individual
signed decision receipt and triaging a failure. The CLI is
`frankenctl verify receipt`; the operator wrapper
`runbooks/scripts/verify_receipt.sh` renders its verdict in plain English and
adds two incident-triage views.

```bash
# verify one receipt, rendering the three layers + targeted remediation
runbooks/scripts/verify_receipt.sh --input verifier_input.json --receipt-id <id>

# also surface the decision posterior snapshot the receipt binds
runbooks/scripts/verify_receipt.sh --input verifier_input.json --receipt-id <id> \
    --show-posterior-path

# also surface the transparency-log inclusion/consistency proofs + provenance chain
runbooks/scripts/verify_receipt.sh --input verifier_input.json --receipt-id <id> \
    --show-evidence-chain

# offline render/triage of a previously emitted verdict (no engine build required)
runbooks/scripts/verify_receipt.sh --receipt-id <id> --verdict-json verdict.json

# self-check the wrapper's rendering/extraction against built-in fixtures
runbooks/scripts/verify_receipt.sh selftest
```

Exit codes: `0` receipt verified · `1` usage/environment error (missing args,
`jq`, or `frankenctl`) · `2` verifier ran but the receipt **failed**.

**The verdict has three independent layers** (`UnifiedReceiptVerificationVerdict`):

| Layer | What it proves | Failure class |
|---|---|---|
| `signature` | The receipt carries a valid threshold signature from the attested signing quorum. | `Signature` |
| `transparency` | The receipt is included in the transparency log and the log is internally consistent. | `Transparency` |
| `attestation` | The producing runtime presented a valid, fresh TEE quote. | `Attestation` |

A `StaleData` failure class means the verifier input itself is outside the
accepted timestamp/epoch window — re-export `verifier_input.json` and re-run.

**Reading inclusion + consistency proofs** (transparency layer): `--show-evidence-chain`
prints each `LayerCheck` (`check`, `outcome`, `detail`) for the transparency layer:

- `mmr_inclusion` — the receipt's leaf is provably under the published log root.
  A `fail` here means the receipt is **not in the published log**: the log
  operator either never included it or is equivocating/omitting it. The decision
  is not publicly auditable — treat as untrusted and escalate to the
  log-operator on-call.
- `mmr_consistency` — the new checkpoint is an append-only extension of the prior
  checkpoint. A `fail` here means the log was **forked or rewritten** between
  checkpoints (history was altered). This is a transparency-log integrity
  incident, not a single-receipt problem — freeze promotions and escalate.

**"Attestation degraded to safe-mode"** (failure class `Attestation`): the runtime
could not validate its TEE quote (typically a stale quote or a measurement that no
longer matches `tee_attestation_policy`). It therefore **drops to safe-mode**: it
keeps running but only under the restricted capability posture, refusing any
attested-only operation, because it can no longer prove it is executing inside a
trusted enclave. Operationally: do **not** promote any decision that requires a
trusted enclave while a receipt verifies with `failure_class=Attestation`;
re-attest (refresh the quote / reconcile the measurement) and re-run the verifier
before lifting the safe-mode posture.

**Operator override (manual halt).** When `verify_receipt.sh` exits non-zero on a
production receipt, halt promotion of the bound decision (`decision_id` /
`policy_id` shown in the output and via `--show-posterior-path`) until the failure
class is resolved. The verifier is fail-closed by design — a non-zero exit is an
instruction to stop, not a warning to note.

> **Pending:** the frankentui "receipt verifier" panel (renders this wrapper's
> output interactively) is tracked separately under Track A as it lives in
> `/dp/frankentui`; the CLI wrapper above is the authoritative operator surface.

---

## RGC Docs and Help Surface Audit

The shipped CLI contract above is guarded by an explicit docs/help audit pack so
README examples do not drift back toward aspirational subcommands.
The replay wrapper resolves the latest complete audit bundle, warns on
incomplete newest runs, and prints the manifest, events, commands, report,
captured help output, and first step log.

- `docs/RGC_DOCS_HELP_SURFACE_AUDIT_V1.md`
- `docs/rgc_docs_help_surface_audit_v1.json`
- `./scripts/run_rgc_docs_help_surface_audit.sh ci`
- `./scripts/e2e/rgc_docs_help_surface_audit_replay.sh ci`

## RGC Zero-Placeholder Gate

`bd-1lsy.9.5` hardens the shipped surface against placeholder regressions with
two complementary operator lanes:

- `./scripts/run_rgc_zero_placeholder_scan.sh ci`
- `./scripts/e2e/rgc_zero_placeholder_scan_replay.sh ci`
- `./scripts/run_rgc_zero_placeholder_gate.sh ci`
- `./scripts/e2e/rgc_zero_placeholder_gate_replay.sh ci`

The gate runner wraps the existing zero-placeholder inventory in a release-style
verdict and emits:

- `placeholder_gate_report.json`
- `waiver_manifest.json`
- `run_manifest.json`
- `trace_ids.json`
- `events.jsonl`
- `commands.txt`

Pass an explicit waiver bundle with
`RGC_ZERO_PLACEHOLDER_GATE_WAIVERS=/abs/path/waivers.json` when a time-bounded
waiver is intentionally part of the evaluation.

## Swarm Responsiveness Claim Map

`bd-bdrwq.11` keeps the swarm-responsiveness track fail-closed by mapping each
child claim surface to its current proof state. Published surfaces carry source
or artifact links plus verification commands; implemented or blocked surfaces
stay explicitly unpublished until their links and focused proof are complete.

- `docs/rgc_swarm_responsiveness_claim_map_v1.json`
- `./scripts/e2e/rgc_swarm_responsiveness_claim_map_smoke.sh check`
- `./scripts/e2e/rgc_swarm_responsiveness_claim_map_smoke.sh selftest`

## Module Composition Claim Ledger

`bd-37q56` records high-value operator-facing composition claims from README,
docs, and source-level module contracts in one fail-closed ledger. The smoke
gate keeps the ledger honest by checking stable claim ordering, source-span
fragments, child-substrate paths, and provisional fallback metadata. `bd-tl6l7`
adds the drift gate, which fails when a claimed parent surface no longer shows
the required child-surface evidence or when it falls back to an undeclared
proxy or heuristic path. `bd-qg92c` adds the artifact-emitting runner and replay
surface so operators can see whether each claim is currently `valid`,
`provisional`, or `unpublished`, along with the exact module links and
remediation text that justify that status.

- `docs/rgc_module_composition_claim_ledger_v1.json`
- `./scripts/e2e/rgc_module_composition_claim_ledger_smoke.sh check`
- `./scripts/e2e/rgc_module_composition_claim_ledger_smoke.sh selftest`
- `./scripts/e2e/rgc_module_composition_drift_gate.sh check`
- `./scripts/e2e/rgc_module_composition_drift_gate.sh selftest`
- `./scripts/run_rgc_module_composition_drift_gate.sh ci`
- `./scripts/run_rgc_module_composition_drift_gate.sh selftest`
- `./scripts/e2e/rgc_module_composition_drift_replay.sh ci`

The runner emits:

- `composition_drift_report.json`
- `composition_drift_summary.md`
- `claim_module_links.json`
- `claim_statuses.json`
- `manifest.json`

Interpretation:
- `valid` means an observed claim still exposes all required child evidence and no undeclared proxy path.
- `provisional` means the declared fallback state is still truthful, but the claim must not be upgraded to observed yet.
- `unpublished` means the operator should either wire the missing child/proof surface or downgrade the claim wording before presenting it as observed behavior.

## Semantic Dark-Matter Pipeline Proof Suite

`bd-6bs27` upgrades the parent `rgc_707_semantic_dark_matter_engine` claim to
an observed surface now that novelty scoring, synthesis receipts, and
saturation-gate receipts are all wired into the parent discovery cycle. The
proof lane stays focused on the real composed integration target and emits a
deterministic artifact bundle that operators can replay without reconstructing
chat history.

- `docs/rgc_module_composition_claim_ledger_v1.json`
- `./scripts/run_semantic_dark_matter_pipeline_suite.sh ci`
- `./scripts/e2e/semantic_dark_matter_pipeline_replay.sh ci`
- `./scripts/e2e/semantic_dark_matter_pipeline_docs_truth_gate.sh check`
- `./scripts/e2e/semantic_dark_matter_pipeline_docs_truth_gate.sh selftest`

The runner emits:

- `artifacts/semantic_dark_matter_pipeline/<timestamp>/run_manifest.json`
- `artifacts/semantic_dark_matter_pipeline/<timestamp>/events.jsonl`
- `artifacts/semantic_dark_matter_pipeline/<timestamp>/commands.txt`
- `artifacts/semantic_dark_matter_pipeline/<timestamp>/summary.md`
- `artifacts/semantic_dark_matter_pipeline/<timestamp>/step_logs/step_*.log`

Replay the latest complete bundle with:

- `./scripts/e2e/semantic_dark_matter_pipeline_replay.sh ci`

Replay a specific preserved run directory with:

- `SEMANTIC_DARK_MATTER_PIPELINE_REPLAY_RUN_DIR=artifacts/semantic_dark_matter_pipeline/<timestamp> ./scripts/e2e/semantic_dark_matter_pipeline_replay.sh ci`

## RGC Compound JSON Runtime Proof Lanes

Compound `JSON.parse` / `JSON.stringify` semantics are defined in
[`docs/RGC_COMPOUND_JSON_RUNTIME_CONTRACT_V1.md`](./docs/RGC_COMPOUND_JSON_RUNTIME_CONTRACT_V1.md).
`bd-2muur.1.3` and `bd-2muur.1.4` provide the shipped proof lanes that show the
runtime traverses heap-backed compound values and that the old placeholder
strings remain closed in the zero-placeholder inventory.

- `./scripts/run_rgc_json_stringify_compound_traversal.sh ci`
- `./scripts/e2e/rgc_json_stringify_compound_traversal_replay.sh ci`
- `./scripts/run_rgc_json_compound_placeholder_closure.sh ci`
- `./scripts/e2e/rgc_json_compound_placeholder_closure_replay.sh ci`

These lanes emit:

- `json_stringify_compound_traversal_report.json`
- `json_compound_placeholder_closure_report.json`
- `run_manifest.json`
- `trace_ids.json`
- `events.jsonl`
- `commands.txt`
- `step_logs/step_*.log`

## Parser Oracle Missing-Artifact Contract

`bd-2muur.7.1` and `bd-2muur.7.2` replace anonymous parser-oracle placeholder
backfills with typed receipts and explicit degraded-mode evidence. The contract
document lives in
[`docs/PARSER_ORACLE_MISSING_ARTIFACT_CONTRACT_V1.md`](./docs/PARSER_ORACLE_MISSING_ARTIFACT_CONTRACT_V1.md),
and the gate behavior is documented in
[`docs/PARSER_ORACLE_GATE.md`](./docs/PARSER_ORACLE_GATE.md).

- `./scripts/run_parser_oracle_missing_artifact_contract.sh ci`
- `./scripts/e2e/parser_oracle_missing_artifact_contract_replay.sh ci`
- `./scripts/run_parser_oracle_missing_artifact_writer.sh ci`
- `./scripts/e2e/parser_oracle_missing_artifact_writer_replay.sh ci`

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

## Parser Phase0 Artifact Contract

`bd-2muur.6.1` defines the truthful performance-artifact contract for the
parser phase0 lane and the explicit degraded-mode receipt path that future
generator work must satisfy instead of emitting placeholder visuals.

```bash
# parser phase0 artifact contract gate (rch-backed check + test + clippy)
./scripts/run_parser_phase0_artifact_contract.sh ci

# deterministic replay wrapper
./scripts/e2e/parser_phase0_artifact_contract_replay.sh ci
```

Contract and vectors:

- [`docs/PARSER_PHASE0_ARTIFACT_CONTRACT_V1.md`](./docs/PARSER_PHASE0_ARTIFACT_CONTRACT_V1.md)
- `docs/parser_phase0_artifact_contract_v1.json`
- `crates/franken-engine/tests/parser_phase0_artifact_contract.rs`

Artifacts are written under:

- `artifacts/parser_phase0_artifact_contract/<timestamp>/run_manifest.json`
- `artifacts/parser_phase0_artifact_contract/<timestamp>/trace_ids.json`
- `artifacts/parser_phase0_artifact_contract/<timestamp>/events.jsonl`
- `artifacts/parser_phase0_artifact_contract/<timestamp>/commands.txt`
- `artifacts/parser_phase0_artifact_contract/<timestamp>/parser_phase0_artifact_contract.json`
- `artifacts/parser_phase0_artifact_contract/<timestamp>/parser_phase0_artifact_contract_validation_report.json`
- `artifacts/parser_phase0_artifact_contract/<timestamp>/step_logs/step_*.log`

## Parser Frontier Harness

`bd-1lsy.2.6.4` aggregates the existing parser frontier proof surfaces into one
replayable harness: the optional-chaining suite, the tagged-template/meta-property
frontier suite, and the parser-gap inventory bundle.

```bash
# parser frontier harness (rch-backed child suites + parser-gap inventory + contract checks)
./scripts/run_parser_frontier_harness.sh ci

# deterministic replay wrapper
./scripts/e2e/parser_frontier_harness_replay.sh full ci
```

Artifacts are written under:

- `artifacts/parser_frontier_harness/<timestamp>/run_manifest.json`
- `artifacts/parser_frontier_harness/<timestamp>/events.jsonl`
- `artifacts/parser_frontier_harness/<timestamp>/commands.txt`
- `artifacts/parser_frontier_harness/<timestamp>/trace_ids.json`
- `artifacts/parser_frontier_harness/<timestamp>/parser_gap_report.json`
- `artifacts/parser_frontier_harness/<timestamp>/case_diagnostics/*.json`

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

## Lowering Gap Truth Invariant

`bd-2muur.4.1` defines the machine-readable invariant that binds lowering-gap
`status`, `parser_ready_syntax`, `execution_ready_semantics`, and the
operator-facing prose fields. The contract exists so `bd-2muur.4.2` can apply a
truthful model to the generator without inventing ad hoc rules at edit time,
and so `bd-2muur.4.3` can align consumers to the same story.

```bash
# lowering-gap truth invariant validation (rch-backed focused test lane)
./scripts/run_lowering_gap_truth_invariant.sh ci

# deterministic replay wrapper
./scripts/e2e/lowering_gap_truth_invariant_replay.sh ci
```

Contract and vectors:

- [`docs/LOWERING_GAP_TRUTH_INVARIANT_V1.md`](./docs/LOWERING_GAP_TRUTH_INVARIANT_V1.md)
- `docs/lowering_gap_truth_invariant_v1.json`
- `crates/franken-engine/tests/lowering_gap_truth_invariant.rs`

Artifacts are written under:

- `artifacts/lowering_gap_truth_invariant/<timestamp>/run_manifest.json`
- `artifacts/lowering_gap_truth_invariant/<timestamp>/trace_ids.json`
- `artifacts/lowering_gap_truth_invariant/<timestamp>/events.jsonl`
- `artifacts/lowering_gap_truth_invariant/<timestamp>/commands.txt`
- `artifacts/lowering_gap_truth_invariant/<timestamp>/step_logs/step_000.log`
- `artifacts/lowering_gap_truth_invariant/<timestamp>/lowering_gap_truth_invariant.json`
- `artifacts/lowering_gap_truth_invariant/<timestamp>/lowering_gap_truth_invariant_validation_report.json`

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
`run_manifest.json`, `matrix_summary.json`, and the `gate_completed`
`events.jsonl` row include deterministic
`matrix_input_status` (`pending_upstream_matrix`, `incomplete_matrix`,
`blocked_critical_deltas`, `ready_for_external_rerun`) plus
`missing_required_inputs` for downstream gating and exact blocker reporting.

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

The replay wrapper now chooses the latest complete artifact directory and
ignores scratch-only partial directories from interrupted/fallback-detected
matrix runs, warning when it has to skip an incomplete newest directory and
failing non-zero if no complete artifact directory exists.

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

# or let the gate auto-discover the latest local PSRP-07.2 matrix bundle
./scripts/run_parser_third_party_rerun_kit.sh package

# one-command replay wrapper
./scripts/e2e/parser_third_party_rerun_kit_replay.sh
```

The replay wrapper fails closed on incomplete newest directories and, when a
newer partial bundle exists, warns and replays the latest complete directory
instead. It prints the full operator-facing artifact set for the selected run:
`run_manifest.json`, `rerun_kit_index.json`, `events.jsonl`, `commands.txt`,
`verifier_notes.md`, and the first `step_logs/step_*.log`.

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

The rerun-kit gate defaults `CARGO_TARGET_DIR` to a repo-local
`target_rch_parser_third_party_rerun_kit_<timestamp>_<pid>` path and records
matrix input provenance (`env`, `auto_discovered`, `missing`) in both
`run_manifest.json` and `rerun_kit_index.json`.

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
evidence. The runner defaults `rch` builds into a repo-local
`target_rch_parser_performance_promotion_gate_<mode>_<pid>` path so remote
workers are not forced through `/tmp`-backed incremental state.

```bash
# parser performance promotion gate (rch-backed check + test + clippy)
./scripts/run_parser_performance_promotion_gate.sh ci

# one-command replay wrapper
./scripts/e2e/parser_performance_promotion_gate_replay.sh
```

The replay wrapper prints the latest complete artifact bundle and warns when it
has to skip a newer incomplete run directory, so operators do not accidentally
triage against partial output.
If an operator aborts a hanging run or the shell terminates mid-step, the
runner still leaves `run_manifest.json`, `events.jsonl`, `commands.txt`, and
`step_000.log` anchored to the in-flight command instead of a step-log-only
partial bundle.

Contract and vectors:

- [`docs/PARSER_PERFORMANCE_PROMOTION_GATE.md`](./docs/PARSER_PERFORMANCE_PROMOTION_GATE.md)
- `crates/franken-engine/tests/fixtures/parser_performance_promotion_gate_v1.json`
- `crates/franken-engine/tests/parser_performance_promotion_gate.rs`

Artifacts are written under:

- `artifacts/parser_performance_promotion_gate/<timestamp>/run_manifest.json`
- `artifacts/parser_performance_promotion_gate/<timestamp>/events.jsonl`
- `artifacts/parser_performance_promotion_gate/<timestamp>/commands.txt`
- `artifacts/parser_performance_promotion_gate/<timestamp>/step_logs/step_*.log`

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
The gate now defaults heavy remote cargo work into a repo-local
`target_rch_parser_operator_developer_runbook_<mode>_<pid>` target directory so
fresh-operator reruns do not depend on fragile `/tmp` worker state. Compile-only
preflight runs `cargo test --no-run` for the integration-test target instead of
`cargo check`, matching the timeout-safe `rch` path used by the shipped lane.

```bash
# parser operator/developer runbook gate (rch-backed check + test + clippy)
./scripts/run_parser_operator_developer_runbook.sh ci

# run scriptable drill mode (includes replay-path validation)
./scripts/run_parser_operator_developer_runbook.sh drill

# one-command replay wrappers
./scripts/e2e/parser_operator_developer_runbook_replay.sh ci
./scripts/e2e/parser_operator_developer_runbook_replay.sh drill
```

The replay wrapper prints the latest complete artifact bundle and warns when it
has to skip a newer incomplete run directory, so fresh operators do not
accidentally triage against partial output. It also states whether the printed
bundle came from the current failed invocation or from an older complete
fallback directory, so operators do not mistake stale evidence for a failed
rerun.
In `drill` mode, the runbook lane reuses the latest complete dependency bundles
from the parser error-recovery and user-impact drill surfaces instead of
rerunning those heavy lanes from scratch.

To inspect a preserved complete bundle without rerunning the lane, point the
wrapper at an exact run directory:

```bash
PARSER_OPERATOR_DEVELOPER_RUNBOOK_REPLAY_RUN_DIR=artifacts/parser_operator_developer_runbook/<timestamp> \
  ./scripts/e2e/parser_operator_developer_runbook_replay.sh ci
```

The explicit run directory must already contain `run_manifest.json`,
`events.jsonl`, `commands.txt`, and `step_logs/step_000.log` or the wrapper
fails closed. The emitted `run_manifest.json` includes that exact preserved-run
replay command in `operator_verification`, so operators can verify both the
rerun path and the no-rerun preserved-bundle path from one manifest.

Contract and vectors:

- [`docs/PARSER_OPERATOR_DEVELOPER_RUNBOOK.md`](./docs/PARSER_OPERATOR_DEVELOPER_RUNBOOK.md)
- `crates/franken-engine/tests/fixtures/parser_operator_developer_runbook_v1.json`
- `crates/franken-engine/tests/parser_operator_developer_runbook.rs`

Artifacts are written under:

- `artifacts/parser_operator_developer_runbook/<timestamp>/run_manifest.json`
- `artifacts/parser_operator_developer_runbook/<timestamp>/events.jsonl`
- `artifacts/parser_operator_developer_runbook/<timestamp>/commands.txt`
- `artifacts/parser_operator_developer_runbook/<timestamp>/step_logs/step_*.log`

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

## RGC Observability Publication Policy Gate

`bd-1lsy.11.20.3` turns observability-on publication into a fail-closed
operator lane by composing calibration sentinels, supremacy-cell attribution,
claim-delta reporting, demotion receipts, and support-bundle attestation into
one deterministic bundle.

```bash
# RGC observability publication policy gate (rch-backed bundle/check/test/clippy)
./scripts/run_rgc_observability_publication_policy.sh ci

# deterministic replay wrapper
./scripts/e2e/rgc_observability_publication_policy_replay.sh ci
```

The replay wrapper resolves the latest complete artifact bundle, warns when it
skips a newer incomplete run directory, and supports exact preserved-run replay
without rerunning the lane via
`RGC_OBSERVABILITY_PUBLICATION_POLICY_REPLAY_RUN_DIR=artifacts/rgc_observability_publication_policy/<timestamp>`.

Contract and integration surface:

- [`docs/RGC_OBSERVABILITY_PUBLICATION_POLICY_V1.md`](./docs/RGC_OBSERVABILITY_PUBLICATION_POLICY_V1.md)
- `docs/rgc_observability_publication_policy_v1.json`
- `crates/franken-engine/src/observability_publication_bundle.rs`
- `crates/franken-engine/src/bin/franken_observability_publication_bundle.rs`
- `crates/franken-engine/tests/observability_publication_bundle_integration.rs`

Artifacts are written under:

- `artifacts/rgc_observability_publication_policy/<timestamp>/run_manifest.json`
- `artifacts/rgc_observability_publication_policy/<timestamp>/events.jsonl`
- `artifacts/rgc_observability_publication_policy/<timestamp>/commands.txt`
- `artifacts/rgc_observability_publication_policy/<timestamp>/trace_ids`
- `artifacts/rgc_observability_publication_policy/<timestamp>/step_logs/`
- `artifacts/rgc_observability_publication_policy/<timestamp>/observability_budget_sentinel_report.json`
- `artifacts/rgc_observability_publication_policy/<timestamp>/observability_on_supremacy_matrix.json`
- `artifacts/rgc_observability_publication_policy/<timestamp>/observability_claim_delta_report.json`
- `artifacts/rgc_observability_publication_policy/<timestamp>/telemetry_demotion_receipts.json`
- `artifacts/rgc_observability_publication_policy/<timestamp>/observability_publication_policy.json`
- `artifacts/rgc_observability_publication_policy/<timestamp>/support_bundle_observability_attestation.json`

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

## RGC Certified Optimization Harness

`bd-1lsy.7.7` now has a parent-level certified-optimization harness that
aggregates the existing rewrite-pack, translation-validation receipt, and
governance modules into one replayable lane with a machine-readable proof
index.

```bash
# certified optimization harness (rch-backed check + test + clippy)
./scripts/run_rgc_certified_optimization_harness.sh ci

# deterministic replay wrapper
./scripts/e2e/rgc_certified_optimization_harness_replay.sh ci
```

Artifacts are written under:

- `artifacts/rgc_certified_optimization_harness/<timestamp>/run_manifest.json`
- `artifacts/rgc_certified_optimization_harness/<timestamp>/events.jsonl`
- `artifacts/rgc_certified_optimization_harness/<timestamp>/commands.txt`
- `artifacts/rgc_certified_optimization_harness/<timestamp>/trace_ids.json`
- `artifacts/rgc_certified_optimization_harness/<timestamp>/rewrite_proof_index.json`
- `artifacts/rgc_certified_optimization_harness/<timestamp>/egraph_rewrite_pack.json`
- `artifacts/rgc_certified_optimization_harness/<timestamp>/rch-log.*`

`check` mode emits only `run_manifest.json`, `events.jsonl`, `commands.txt`,
and retained `rch-log.*` artifacts. `test` and `ci` additionally emit
`trace_ids.json`, `rewrite_proof_index.json`, and `egraph_rewrite_pack.json`.

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

## Cross-Repo Integration Suite

`bd-1mgd` aggregates the existing cross-repo contract lanes for
`/dp/asupersync`, `/dp/frankentui`, `/dp/frankensqlite`, `/dp/fastapi_rust`,
and the `sqlmodel_rust` boundary inventory.

```bash
# Cross-repo integration suite (rch-backed check + test + clippy)
./scripts/run_cross_repo_integration_suite.sh ci
```

Deterministic replay wrapper:

```bash
./scripts/e2e/cross_repo_integration_suite_replay.sh
```

Artifacts are written under:

- `artifacts/cross_repo_integration_suite/<timestamp>/run_manifest.json`
- `artifacts/cross_repo_integration_suite/<timestamp>/events.jsonl`
- `artifacts/cross_repo_integration_suite/<timestamp>/commands.txt`
- `artifacts/cross_repo_integration_suite/<timestamp>/asupersync_contract_matrix/`

## RGC FrankenNode Handoff Bundle Gate

`bd-1lsy.5.10.3` packages the engine-owned support-surface contract and blocker
ledger into a deterministic handoff bundle for `/dp/franken_node`, with
sibling smoke checks and fail-closed routing when upstream evidence is missing,
stale, or orphaned.

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

The replay wrapper resolves the latest complete handoff bundle, warns when it
must skip a newer incomplete run directory, and fails closed if no complete
bundle exists. When `RGC_FRANKEN_NODE_HANDOFF_BUNDLE_REPLAY_RUN_DIR` is set,
the wrapper replays that exact preserved bundle instead of rerunning the lane;
the directory must already contain the full artifact set or replay fails
closed.

Artifacts are written under:

- `artifacts/rgc_franken_node_handoff_bundle/<timestamp>/run_manifest.json`
- `artifacts/rgc_franken_node_handoff_bundle/<timestamp>/events.jsonl`
- `artifacts/rgc_franken_node_handoff_bundle/<timestamp>/commands.txt`
- `artifacts/rgc_franken_node_handoff_bundle/<timestamp>/trace_ids.json`
- `artifacts/rgc_franken_node_handoff_bundle/<timestamp>/franken_node_handoff_manifest.json`
- `artifacts/rgc_franken_node_handoff_bundle/<timestamp>/sibling_smoke_verification.json`
- `artifacts/rgc_franken_node_handoff_bundle/<timestamp>/support_surface_summary.md`
- `artifacts/rgc_franken_node_handoff_bundle/<timestamp>/franken_node_handoff_bundle_contract.json`
- `artifacts/rgc_franken_node_handoff_bundle/<timestamp>/support_surface_contract.json`
- `artifacts/rgc_franken_node_handoff_bundle/<timestamp>/engine_product_blocker_ledger.json`
- `artifacts/rgc_franken_node_handoff_bundle/<timestamp>/repo_split_contract.md`
- `artifacts/rgc_franken_node_handoff_bundle/<timestamp>/step_logs/step_000.log`

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

## RGC Module Interop Verification Matrix Gate

`bd-1lsy.11.8` ships the verification gate, while `bd-1lsy.5.2` supplies the
default CommonJS/ESM interop contract that the matrix replays against Node and
Bun reference behavior plus FrankenEngine `native`, `node_compat`, and
`bun_compat` modes. The gate makes mode-sensitive divergences explicit,
including `ERR_REQUIRE_ESM` fail-closed behavior in `native`/`node_compat` and
the documented `bun_compat` bridge cases. The matrix also pins npm-style
`pkg.js` / `@scope/pkg.js` extension-probe package entries so nested `./sub`
requires stay anchored to the package root. `package.json` `type=module`
extensionless relative imports stay fail-closed in `native`/`node_compat`;
only the explicit `bun_compat` bridge enables extension probing.

```bash
# RGC module interop verification matrix gate (rch-backed check + test + clippy)
./scripts/run_rgc_module_interop_verification_matrix.sh ci

# deterministic replay wrapper for an exact emitted run directory
RGC_MODULE_INTEROP_MATRIX_REPLAY_RUN_DIR=artifacts/... \
  ./scripts/e2e/rgc_module_interop_verification_matrix_replay.sh
```

Contract and vectors:

- `docs/module_compatibility_matrix_v1.json`
- `crates/franken-engine/tests/module_compatibility_matrix.rs`
- `crates/franken-engine/tests/module_compatibility_matrix_integration.rs`

Artifacts are written under:

- `artifacts/rgc_module_interop_verification_matrix/<timestamp>/run_manifest.json`
- `artifacts/rgc_module_interop_verification_matrix/<timestamp>/events.jsonl`
- `artifacts/rgc_module_interop_verification_matrix/<timestamp>/commands.txt`
- `artifacts/rgc_module_interop_verification_matrix/<timestamp>/trace_ids.json`
- `artifacts/rgc_module_interop_verification_matrix/<timestamp>/module_resolution_trace.jsonl`
- `artifacts/rgc_module_interop_verification_matrix/<timestamp>/step_logs/step_*.log`

Operator verification:

```bash
cat artifacts/rgc_module_interop_verification_matrix/<timestamp>/run_manifest.json
cat artifacts/rgc_module_interop_verification_matrix/<timestamp>/events.jsonl
cat artifacts/rgc_module_interop_verification_matrix/<timestamp>/commands.txt
cat artifacts/rgc_module_interop_verification_matrix/<timestamp>/module_resolution_trace.jsonl
cat artifacts/rgc_module_interop_verification_matrix/<timestamp>/trace_ids.json
cat artifacts/rgc_module_interop_verification_matrix/<timestamp>/step_logs/step_000.log

./scripts/e2e/rgc_module_resolution_trace_contract_smoke.sh \
  artifacts/rgc_module_interop_verification_matrix/<timestamp>/module_resolution_trace.jsonl

rg -n 'compatibility_disposition|remediation_guidance' \
  crates/franken-engine/src/esm_cjs_interop_parity.rs

RGC_MODULE_INTEROP_MATRIX_REPLAY_RUN_DIR=artifacts/... \
  ./scripts/e2e/rgc_module_interop_verification_matrix_replay.sh
```

## RGC NPM Compatibility Matrix Gate

`bd-1lsy.5.4` turns npm ecosystem truth into a deterministic, replayable
artifact lane. The shipped matrix records Tier 1 critical, Tier 2 popular, and
Tier 3 long-tail cohorts; per-package compatibility outcomes; minimized repros;
and unresolved failure owner routing instead of anonymous ecosystem claims.

```bash
# RGC npm compatibility matrix gate (rch-backed check + test + clippy + run)
./scripts/run_rgc_npm_compatibility_matrix.sh ci

# deterministic replay wrapper for an exact emitted run directory
RGC_NPM_COMPATIBILITY_MATRIX_REPLAY_RUN_DIR=artifacts/... \
  ./scripts/e2e/rgc_npm_compatibility_matrix_replay.sh ci
```

The replay wrapper resolves the latest complete run directory, warns when it
has to skip a newer incomplete directory, and fails closed on incomplete
explicit run directories.

Contract and vectors:

- [`docs/RGC_NPM_COMPATIBILITY_MATRIX_V1.md`](./docs/RGC_NPM_COMPATIBILITY_MATRIX_V1.md)
- `docs/rgc_npm_compatibility_matrix_v1.json`
- `crates/franken-engine/src/npm_compatibility_matrix.rs`
- `crates/franken-engine/src/bin/franken_npm_compatibility_matrix.rs`
- `crates/franken-engine/tests/npm_compatibility_matrix_cli.rs`
- `crates/franken-engine/tests/npm_compatibility_matrix_enrichment_integration.rs`

Artifacts are written under:

- `artifacts/rgc_npm_compatibility_matrix/<timestamp>/npm_compat_matrix_report.json`
- `artifacts/rgc_npm_compatibility_matrix/<timestamp>/trace_ids.json`
- `artifacts/rgc_npm_compatibility_matrix/<timestamp>/run_manifest.json`
- `artifacts/rgc_npm_compatibility_matrix/<timestamp>/events.jsonl`
- `artifacts/rgc_npm_compatibility_matrix/<timestamp>/commands.txt`

Operator verification:

```bash
cat artifacts/rgc_npm_compatibility_matrix/<timestamp>/npm_compat_matrix_report.json
cat artifacts/rgc_npm_compatibility_matrix/<timestamp>/trace_ids.json
cat artifacts/rgc_npm_compatibility_matrix/<timestamp>/run_manifest.json
cat artifacts/rgc_npm_compatibility_matrix/<timestamp>/events.jsonl
cat artifacts/rgc_npm_compatibility_matrix/<timestamp>/commands.txt
jq '.unresolved_failures' artifacts/rgc_npm_compatibility_matrix/<timestamp>/npm_compat_matrix_report.json

RGC_NPM_COMPATIBILITY_MATRIX_REPLAY_RUN_DIR=artifacts/... \
  ./scripts/e2e/rgc_npm_compatibility_matrix_replay.sh ci
```

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

## Scientific Contribution Targets Gate

`bd-2501` turns the Section 16 research-output obligations into a
deterministic, fail-closed status bundle. The lane stays red until milestone
beads `bd-2501.1`, `bd-2501.2`, and `bd-2501.3` close and the upstream
evidence dependencies remain closed.

```bash
# status bundle (expected to fail closed while milestone beads remain open)
./scripts/run_scientific_contribution_targets.sh bundle

# full gate (bundle + rch-backed cargo check/test/clippy)
./scripts/run_scientific_contribution_targets.sh ci

# replay the latest complete status bundle
./scripts/e2e/scientific_contribution_targets_replay.sh show
```

Contract and vectors:

- [`docs/SCIENTIFIC_CONTRIBUTION_TARGETS_V1.md`](./docs/SCIENTIFIC_CONTRIBUTION_TARGETS_V1.md)
- [`docs/SCIENTIFIC_REPORT_CATALOG_V1.md`](./docs/SCIENTIFIC_REPORT_CATALOG_V1.md)
- [`docs/EXTERNAL_REPLICATION_CATALOG_V1.md`](./docs/EXTERNAL_REPLICATION_CATALOG_V1.md)
- [`docs/OPEN_TOOL_ADOPTION_CATALOG_V1.md`](./docs/OPEN_TOOL_ADOPTION_CATALOG_V1.md)
- `docs/scientific_contribution_targets_v1.json`
- `docs/scientific_report_catalog_v1.json`
- `docs/external_replication_catalog_v1.json`
- `docs/open_tool_adoption_catalog_v1.json`
- `scripts/run_scientific_contribution_targets.sh`
- `scripts/e2e/scientific_contribution_targets_replay.sh`
- `crates/franken-engine/tests/scientific_contribution_targets.rs`

Artifacts are written under:

- `artifacts/scientific_contribution_targets/<timestamp>/run_manifest.json`
- `artifacts/scientific_contribution_targets/<timestamp>/events.jsonl`
- `artifacts/scientific_contribution_targets/<timestamp>/commands.txt`
- `artifacts/scientific_contribution_targets/<timestamp>/trace_ids.json`
- `artifacts/scientific_contribution_targets/<timestamp>/contribution_status_report.json`
- `artifacts/scientific_contribution_targets/<timestamp>/output_contract_status_report.json`
- `artifacts/scientific_contribution_targets/<timestamp>/dependency_status_report.json`
- `artifacts/scientific_contribution_targets/<timestamp>/technical_report_status_report.json`
- `artifacts/scientific_contribution_targets/<timestamp>/external_replication_status_report.json`
- `artifacts/scientific_contribution_targets/<timestamp>/open_tool_adoption_status_report.json`
- `artifacts/scientific_contribution_targets/<timestamp>/scientific_contribution_summary.md`
- `artifacts/scientific_contribution_targets/<timestamp>/scientific_contribution_targets_v1.json`
- `artifacts/scientific_contribution_targets/<timestamp>/scientific_contribution_targets_v1.md`
- `artifacts/scientific_contribution_targets/<timestamp>/scientific_report_catalog_v1.json`
- `artifacts/scientific_contribution_targets/<timestamp>/SCIENTIFIC_REPORT_CATALOG_V1.md`
- `artifacts/scientific_contribution_targets/<timestamp>/external_replication_catalog_v1.json`
- `artifacts/scientific_contribution_targets/<timestamp>/EXTERNAL_REPLICATION_CATALOG_V1.md`
- `artifacts/scientific_contribution_targets/<timestamp>/open_tool_adoption_catalog_v1.json`
- `artifacts/scientific_contribution_targets/<timestamp>/OPEN_TOOL_ADOPTION_CATALOG_V1.md`
- `artifacts/scientific_contribution_targets/<timestamp>/step_logs/step_*.log`

Operator verification:

```bash
jq empty docs/scientific_contribution_targets_v1.json
jq empty docs/scientific_report_catalog_v1.json
jq empty docs/external_replication_catalog_v1.json
jq empty docs/open_tool_adoption_catalog_v1.json
./scripts/run_scientific_contribution_targets.sh bundle
./scripts/e2e/scientific_contribution_targets_replay.sh show

rch exec -- env RUSTUP_TOOLCHAIN=nightly \
  CARGO_TARGET_DIR=$PWD/target_rch_scientific_contribution_targets_verify \
  CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 \
  cargo test -p frankenengine-engine --test scientific_contribution_targets
```

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

## RGC Security Enforcement Verification Pack

`bd-1lsy.11.9` adds deterministic adversarial verification for capability
denials, IFC/declassification controls, containment escalation behavior, and
replay-first operator triage.

```bash
# RGC security-enforcement verification pack gate (rch-backed check + test + clippy)
./scripts/run_rgc_security_enforcement_verification_pack.sh ci

# deterministic replay wrapper
./scripts/e2e/rgc_security_enforcement_verification_pack_replay.sh ci

# exact preserved-bundle replay without rerunning the lane
RGC_SECURITY_ENFORCEMENT_VERIFICATION_PACK_REPLAY_RUN_DIR=artifacts/rgc_security_enforcement_verification_pack/<timestamp> \
  ./scripts/e2e/rgc_security_enforcement_verification_pack_replay.sh ci
```

Contract and vectors:

- [`docs/RGC_SECURITY_ENFORCEMENT_VERIFICATION_PACK_V1.md`](./docs/RGC_SECURITY_ENFORCEMENT_VERIFICATION_PACK_V1.md)
- `docs/rgc_security_enforcement_verification_pack_v1.json`
- `docs/rgc_security_enforcement_verification_vectors_v1.json`
- `crates/franken-engine/tests/rgc_security_enforcement_verification_pack.rs`

Artifacts are written under:

- `artifacts/rgc_security_enforcement_verification_pack/<timestamp>/run_manifest.json`
- `artifacts/rgc_security_enforcement_verification_pack/<timestamp>/trace_ids.json`
- `artifacts/rgc_security_enforcement_verification_pack/<timestamp>/events.jsonl`
- `artifacts/rgc_security_enforcement_verification_pack/<timestamp>/commands.txt`
- `artifacts/rgc_security_enforcement_verification_pack/<timestamp>/step_logs/step_*.log`
- `artifacts/rgc_security_enforcement_verification_pack/<timestamp>/security_verification_report.json`

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

## RGC Seqlock Reader/Writer Contract

`bd-1lsy.7.21.2` binds accepted seqlock candidates to deterministic retry
budgets, writer-pressure limits, and incumbent fallback semantics before
rollout is considered.

```bash
# RGC seqlock reader/writer contract suite (rch-backed check + test + clippy + bundle emission)
./scripts/run_seqlock_reader_writer_contract_suite.sh ci

# deterministic replay wrapper
./scripts/e2e/seqlock_reader_writer_contract_replay.sh ci
```

`run_seqlock_reader_writer_contract_suite.sh` defaults `CARGO_TARGET_DIR` to
the stable external path
`/data/tmp/rch_target_franken_engine_seqlock_reader_writer_contract` so `rch`
workers can reuse incremental artifacts without syncing the build tree back
through the workspace. Override with `CARGO_TARGET_DIR=...` if you need
isolated lane-specific builds.

Contract and vectors:

- [`docs/RGC_SEQLOCK_READER_WRITER_CONTRACT_V1.md`](./docs/RGC_SEQLOCK_READER_WRITER_CONTRACT_V1.md)
- `docs/rgc_seqlock_reader_writer_contract_v1.json`
- `crates/franken-engine/src/seqlock_reader_writer_contract.rs`
- `crates/franken-engine/tests/seqlock_reader_writer_contract.rs`

Artifacts are written under:

- `artifacts/seqlock_reader_writer_contract/<timestamp>/run_manifest.json`
- `artifacts/seqlock_reader_writer_contract/<timestamp>/seqlock_reader_writer_contract.json`
- `artifacts/seqlock_reader_writer_contract/<timestamp>/retry_budget_policy.json`
- `artifacts/seqlock_reader_writer_contract/<timestamp>/incumbent_fallback_matrix.json`

## RGC Seqlock Rollout Guard

`bd-1lsy.7.21.3` gates seqlock-backed rollout on deterministic safety-case,
starvation microbench, and loom/model-check evidence, and fails closed until
positive model-check coverage exists for the accepted candidates.

```bash
# RGC seqlock rollout guard suite (rch-backed check + test + clippy + bundle emission)
./scripts/run_seqlock_rollout_guard_suite.sh ci

# deterministic replay wrapper
./scripts/e2e/seqlock_rollout_guard_replay.sh ci
```

`run_seqlock_rollout_guard_suite.sh` defaults `CARGO_TARGET_DIR` to the stable
external path `/data/tmp/rch_target_franken_engine_seqlock_rollout_guard` so
`rch` workers can reuse incremental artifacts without syncing the build tree
back through the workspace. The replay wrapper prints the latest complete suite
manifest, runner manifest, rollout-guard artifact, commands, trace IDs, and
step-log paths, and warns if the newest artifact directory is incomplete.

Contract and vectors:

- [`docs/RGC_SEQLOCK_ROLLOUT_GUARD_V1.md`](./docs/RGC_SEQLOCK_ROLLOUT_GUARD_V1.md)
- `docs/rgc_seqlock_rollout_guard_v1.json`
- `crates/franken-engine/src/seqlock_rollout_guard.rs`
- `crates/franken-engine/tests/seqlock_rollout_guard.rs`

Artifacts are written under:

- `artifacts/seqlock_rollout_guard/<timestamp>/run_manifest.json`
- `artifacts/seqlock_rollout_guard/<timestamp>/events.jsonl`
- `artifacts/seqlock_rollout_guard/<timestamp>/commands.txt`

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
- `artifacts/rgc_cli_operator_workflow_verification_pack/<timestamp>/trace_ids.json`
- `artifacts/rgc_cli_operator_workflow_verification_pack/<timestamp>/events.jsonl`
- `artifacts/rgc_cli_operator_workflow_verification_pack/<timestamp>/commands.txt`
- `artifacts/rgc_cli_operator_workflow_verification_pack/<timestamp>/step_logs/step_*.log`

The verified generic `frankenctl` workflow bundle inspected by this pack also
includes:

- `artifacts/frankenctl_cli_workflow/<timestamp>/support_bundle/index.json`
- `artifacts/frankenctl_cli_workflow/<timestamp>/support_bundle/preflight_report.json`
- `artifacts/frankenctl_cli_workflow/<timestamp>/support_bundle/onboarding_scorecard.json`
- `artifacts/frankenctl_cli_workflow/<timestamp>/support_bundle/rollout_decision_artifact.json`
- `artifacts/frankenctl_cli_workflow/<timestamp>/support_bundle/frankenctl_doctor_report.json`

## RGC Cross-Platform Matrix Gate

`bd-1lsy.11.13` validates runtime and CLI workflow manifests across
Linux/macOS/Windows and x64/arm64 targets, classifies drift with stable
severity codes, and fails closed in `ci` and `matrix` modes when required target
manifests are missing or strict matrix evaluation sees unresolved critical
deltas. The gate can consume explicit per-target manifest env vars or
auto-discover the latest complete manifest set under
`artifacts/rgc_cross_platform_matrix_inputs`.

```bash
# RGC cross-platform matrix gate (rch-backed check + test + clippy + matrix)
./scripts/run_rgc_cross_platform_matrix_gate.sh ci

# deterministic replay / strict matrix wrapper
./scripts/e2e/rgc_cross_platform_matrix_replay.sh matrix
```

Contract and vectors:

- [`docs/RGC_CROSS_PLATFORM_MATRIX_V1.md`](./docs/RGC_CROSS_PLATFORM_MATRIX_V1.md)
- `docs/rgc_cross_platform_matrix_v1.json`
- `crates/franken-engine/tests/rgc_cross_platform_matrix.rs`

Artifacts are written under:

- `artifacts/rgc_cross_platform_matrix/<timestamp>/run_manifest.json`
- `artifacts/rgc_cross_platform_matrix/<timestamp>/events.jsonl`
- `artifacts/rgc_cross_platform_matrix/<timestamp>/commands.txt`
- `artifacts/rgc_cross_platform_matrix/<timestamp>/matrix_target_deltas.jsonl`
- `artifacts/rgc_cross_platform_matrix/<timestamp>/matrix_summary.json`

## RGC Lockstep Oracle Pipeline

`bd-cixqu.9.3` implements the full Node+Bun lockstep oracle pipeline that compares 
FrankenEngine execution against reference runtimes. The gate promotes the lockstep 
oracle from SIMULATED to OBSERVED status by capturing real divergence/convergence 
verdicts with typed evidence atoms per the I.2 divergence classification taxonomy.

### When to Run

Run the lockstep oracle pipeline gate:
- As part of release validation to verify runtime compatibility
- After significant runtime changes to detect regressions  
- When investigating divergence reports from production
- For periodic conformance monitoring against reference implementations

### Usage

```bash
# Full CI mode - tests all workloads
./scripts/run_rgc_lockstep_oracle_pipeline.sh ci

# Development mode - optionally filter to specific workload
./scripts/run_rgc_lockstep_oracle_pipeline.sh dev numeric_loop

# Replay previous run for verification
./scripts/e2e/rgc_lockstep_oracle_pipeline_replay.sh

# Replay specific preserved bundle  
RGC_LOCKSTEP_ORACLE_PIPELINE_REPLAY_RUN_DIR=/path/to/bundle ./scripts/e2e/rgc_lockstep_oracle_pipeline_replay.sh
```

### Artifacts Generated

The gate emits a comprehensive artifact bundle under `artifacts/lockstep_oracle/${timestamp}/`:

**Core Artifacts:**
- `run_manifest.json` - Complete artifact manifest with content hashes
- `events.jsonl` - Structured event log for the entire pipeline
- `commands.txt` - Shell command transcript with environment
- `summary.txt` - Operator-readable summary (5-10 lines)

**Step Logs:**
- `step_logs/step_001_setup.log` - Environment and directory setup
- `step_logs/step_002_build.log` - Lockstep orchestrator compilation
- `step_logs/step_003_workload_generation.log` - Test workload trace generation
- `step_logs/step_004_node_comparison.log` - Node.js vs FrankenEngine comparison
- `step_logs/step_005_bun_comparison.log` - Bun vs FrankenEngine comparison  
- `step_logs/step_006_analysis.log` - Divergence classification and evidence generation

**Trace Data:**
- `workload_traces/node_traces/*.trace.json` - Node.js execution traces
- `workload_traces/bun_traces/*.trace.json` - Bun execution traces
- `workload_traces/franken_traces/*.trace.json` - FrankenEngine execution traces

**Analysis Results:**
- `divergence_reports/node_vs_franken.json` - Node.js comparison results
- `divergence_reports/bun_vs_franken.json` - Bun comparison results
- `divergence_reports/evidence_atoms.jsonl` - Classified divergence evidence

### Reading Divergence Verdicts

Each comparison report contains:

```json
{
  "summary": {
    "total_cases": 5,
    "pass_cases": 4, 
    "failed_cases": 1
  },
  "case_results": [
    {
      "fixture_ref": "numeric_loop",
      "pass": false,
      "divergence": {
        "class": "EventSequence",
        "message": "console_output mismatch: expected '42', got '43'"
      }
    }
  ]
}
```

Evidence atoms in `evidence_atoms.jsonl` provide structured classification:

```json
{
  "schema_version": "franken-engine.divergence-evidence.v1",
  "classification": {
    "EngineBug": {
      "severity": "Minor",
      "reproducer": "Console output mismatch in numeric_loop",
      "expected_behavior": "Output should match Node.js: '42'",
      "actual_behavior": "FrankenEngine outputs: '43'"
    }
  },
  "classification_confidence": "Automated"
}
```

**Classification Types:**
- **EngineBug**: Genuine FrankenEngine bugs (Critical/Major/Minor/Cosmetic)
- **IntentionalImprovement**: Deliberate improvements (Performance/Security/Diagnostics)  
- **CompatibilityDebt**: Known deviations needing ecosystem fixes (Blocker/High/Medium/Low)
- **EcosystemAmbiguity**: Reference disagreements or spec gaps

### Triage Workflow

1. **Check summary.txt** for quick overview of pass/fail rates
2. **Review divergence_reports/** for specific runtime comparison results  
3. **Examine evidence_atoms.jsonl** for classified divergence evidence
4. **Use classification confidence** to prioritize manual review:
   - `Automated` - High confidence, can proceed with triage rules
   - `Tentative` - Requires human investigation  
   - `Disputed` - Needs expert resolution

### Environment Variables

- `RGC_LOCKSTEP_ORACLE_ARTIFACTS_DIR` - Override artifacts directory
- `RGC_LOCKSTEP_ORACLE_WORKLOAD_FILTER` - Filter to specific workloads
- `RGC_LOCKSTEP_ORACLE_PIPELINE_REPLAY_RUN_DIR` - Pin replay to specific bundle

### Integration Points

The lockstep oracle pipeline integrates with:
- **Runtime comparison benchmarks** (I.1) - Generates actual runtime traces
- **Divergence classification taxonomy** (I.2) - Applies typed evidence atoms
- **Evidence ledger system** - Chains evidence for audit trail
- **Operator triage surface** (I.6) - Feeds divergence analysis workflow

## Capability-Typed Compile-Time Rejection Gate

`bd-cixqu.3` (FE-CLAIM-006, Track C) lands the compile-time ambient-authority
rejection contract. The gate refuses to lower a TS source whose call sites
reach a capability surface the calling scope has not declared, and emits a
structured diagnostic naming the source span and the missing capability.

The diagnostic surface and operator workflow described below are anchored
to three already-shipped child beads:

- `bd-cixqu.3.1` (C.1) — typed [`EffectSet`](../../crates/franken-engine/src/effect_set.rs) +
  [`EffectAnnotation`](../../crates/franken-engine/src/effect_set.rs) contract for IR2
  function/method nodes, with policy distinguishability (Empty / Inherited / Declared).
- `bd-cixqu.3.3` (C.3) — 16-entry red-team negative scenario corpus under
  [`crates/franken-engine/tests/red_team_scenarios/`](../../crates/franken-engine/tests/red_team_scenarios/),
  each declaring the expected `LoweringPipelineError` variant in its manifest.
- `bd-cixqu.3.6` (C.6) — `capability_shadowed_import` laundering attempt
  fixture, validated by `red_team_scenario_manifest_validation.rs`.

The gate runner and its replay wrapper (`./scripts/run_rgc_capability_typed_compile_time.sh`
+ `./scripts/e2e/rgc_capability_typed_compile_time_replay.sh`) are tracked
under `bd-cixqu.3.4`; the lowering-side rejection emitter is `bd-cixqu.3.2`.
This section documents the operator-facing contract those beads will satisfy.

### When to run

- Before promoting an extension manifest to a deployment lane.
- After editing source under `extensions/<name>/` whose effect set could
  have changed (any new `require()` / `import` of a host module, any new
  computed-member access on `process` / `globalThis`).
- After any change to a `declare_capability` annotation in source.
- After updates to `effect_set::EffectKind` (schema-bump event).

### Expected artifacts

When the gate runs to completion it emits the following under
`artifacts/rgc_capability_typed_compile_time/<timestamp>/`:

- `capability_rejection_report.json` — list of call sites that were
  refused, the source span of each, and the `EffectSet` that would have
  been required for acceptance.
- `effect_annotation_inventory.json` — every function/method node in the
  lowered IR with its resolved `EffectAnnotation` (policy + effect set).
- `run_manifest.json` — schema id, host facts, content hashes, operator
  verification commands.
- `trace_ids.json` — UUIDv7 trace / decision / policy ids for the run.
- `events.jsonl` — structured event stream including every emitted
  `LoweringPipelineError::UnauthorizedFlow` / `UnsupportedSyntax`.
- `commands.txt` — verbatim shell transcript for replay.

### Interpreting `LoweringPipelineError::AmbientAuthorityViolation`

This diagnostic fires when the lowering pass refuses a call site whose
target reaches an ambient-authority surface that the calling scope has
not declared. Read the fields in this order:

1. **`source_span`** — the file path, line, and column of the rejected
   call site. Open it in your editor before continuing; the rest of the
   diagnostic refers to identifiers visible at that span.
2. **`required_capability`** — the `EffectKind` (e.g. `fs.read`,
   `proc.spawn`, `runtime.eval`) the call site would need to be granted
   for the lowering to accept it. This is the canonical capability id;
   the same string appears in extension manifests and in
   [`docs/CLAIM_TO_PROOF_MATRIX_V1.md`](../CLAIM_TO_PROOF_MATRIX_V1.md).
3. **`calling_scope_effects`** — the resolved `EffectSet` the calling
   scope declared. If this set is empty, the calling scope opted out of
   every capability and the rejection is correct by construction; the
   fix is to declare the capability at the appropriate scope, not to
   widen here.
4. **`evasion_class`** — when the lowering recognises the call site as a
   well-known evasion attempt (capability-shadowed import, computed-member
   access on `process`, `eval` / `new Function`, `Reflect.apply` of an
   ambient target, `with`-block over ambient binding, etc.), this field
   names the matching pattern. The 16-entry red-team scenario corpus is
   the canonical reference for evasion classes.
5. **`chain_root`** — when the rejected binding is reached through a
   transitive re-export chain, this is the original Node module the
   chain root resolves to. A `chain_root` of `child_process` plus an
   `evasion_class` of `capability_shadowed_import` is the canonical
   laundering pattern (see `bd-cixqu.3.6`).

### Operator action: legitimate use case

If the rejected call site is a legitimate use the extension intends to
make, walk through the workflow in
[`docs/operator-gates/ADDING_A_NEW_CAPABILITY.md`](./ADDING_A_NEW_CAPABILITY.md).
That document covers: identifying the required `EffectKind`, editing the
extension manifest to declare it, regenerating the typed-effect
inventory, and rerunning the gate.

### Operator action: bug or laundering attempt

If the rejected call site is *not* a legitimate use — i.e. the evasion
class is one of the catalogued laundering patterns, or the rejected
binding reaches `child_process` / `fs.write` / `runtime.eval` from a
scope that has no business being there — escalate to a security review:

1. Capture the full `capability_rejection_report.json` and
   `events.jsonl` from the gate run.
2. Note the `chain_root` and `evasion_class` in the security ticket.
3. Cross-reference the matching scenario under
   `crates/franken-engine/tests/red_team_scenarios/` if the
   `evasion_class` is one of the 16 catalogued attack vectors.
4. Do NOT add the capability to the manifest as a workaround; the
   intended response is for the extension to stop reaching the surface,
   not for the deployment lane to widen its trust envelope.

### Diagnostic format invariants

The diagnostic message format itself is pinned by ≥20 unit tests on the
`LoweringPipelineError::AmbientAuthorityViolation` rendering (deferred to
the diagnostic implementation in `bd-cixqu.3.2`). The invariants the
tests enforce:

- Every diagnostic carries a non-empty `source_span` and a
  `required_capability` that is a valid `EffectKind::as_str()` value.
- The diagnostic is deterministic across runs given the same inputs —
  identical source plus identical capability manifest produces identical
  diagnostic bytes.
- The diagnostic includes the `bd-cixqu.3` claim id for traceability.
- Field ordering in the rendered text is stable so replay diffs are
  meaningful.

### Integration points

This gate integrates with:

- **EffectSet contract** (`bd-cixqu.3.1`) — every diagnostic
  `required_capability` is an `EffectKind` value.
- **Red-team scenario corpus** (`bd-cixqu.3.3`, `bd-cixqu.3.6`) — the
  `evasion_class` field's value space is the corpus's `attack_vector`
  set.
- **Claim-to-proof matrix** (`docs/CLAIM_TO_PROOF_MATRIX_V1.md`) — every
  `EffectKind` has a row in the matrix declaring its current proof
  state. Promoting a capability from HYPOTHESIS to OBSERVED requires
  this gate to run green against a corpus that exercises the surface.
- **Operator status reports** — the gate's `events.jsonl` feeds the
  operator-status bundle for the deployment lane.

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| Compile artifact verification fails | Source path, parse goal, or artifact contents are stale/mismatched | Rerun `frankenctl compile --input <source.js> --out <artifact.json> --goal <script|module>` and then `frankenctl verify compile-artifact --input <artifact.json>` |
| `doctor` summary reports missing readiness signals | Runtime diagnostics input or optional signal bundles are incomplete | Rebuild the JSON input bundle and rerun `frankenctl doctor --input <runtime_input.json> --summary --out-dir <dir>` |
| Replay mismatch on a captured trace | Snapshot or nondeterminism transcript is incomplete | Rerun `frankenctl replay run --trace <trace.json> --compare-trace <candidate-trace.json> --mode validate --out <report.json>` and inspect the replay report |
| Receipt verification failure | Verifier input is stale or the receipt ID does not match the bundle | Run `frankenctl verify receipt --input <verifier_input.json> --receipt-id <id> --summary` and inspect the rendered verdict |
| Benchmark publication gate fails | Claim bundle or publication input is incomplete, stale, or below the scoring threshold | Run `frankenctl benchmark verify --bundle <dir> --summary --output <report.json>` and `frankenctl benchmark score --input <publication_gate_input.json> --output <results.json>` |

## Universal artifact publication enforcement

(Added by `bd-cixqu.4.5` — companion to the `bd-cixqu.4.3` gate
extension and the `bd-cixqu.4.4` matrix promotion.)

### What enforces what

The matrix gate at `scripts/run_claim_to_proof_matrix_gate.sh` (see
also the [Claim-to-Proof Matrix Gate](#) section above) was extended
by `bd-cixqu.4.3` so that any row in `docs/claim_to_proof_matrix_v1.json`
with `allowed_state == "observed"` is rejected unless its
`artifact_path` has a sibling `repro.lock` file conforming to
`docs/REPRODUCIBILITY_CONTRACT.md`. Rejection emits the stable error
code `ClaimMatrixError::MissingReproducibilityBundle` in the structured
event log and on stderr.

`FE-CLAIM-009` ("Every published performance and security claim ships
with reproducible artifact bundles.") is itself OBSERVED as of
`bd-cixqu.4.4` (commit `1b0de84c`); the gate now self-attests against
its own contract.

### What the error message means

```
FE-CLAIM-XXX: ClaimMatrixError::MissingReproducibilityBundle: observed claim artifact has no repro.lock alongside <path>; reproducibility lock is required for any claim whose allowed_state is 'observed' (bd-cixqu.4.3)
```

Translation: the matrix row claims this is OBSERVED, but the
artifact-publication contract was not satisfied for the matched
bundle. Either the bundle was never written (gate run never produced
a `repro.lock`), the bundle was moved/renamed, or the row points at
the wrong path.

### How to remediate

1. Audit which rows are missing locks:

   ```
   runbooks/scripts/audit_repro_lock_coverage.sh
   ```

   Output: per-claim `lock_status` (present / missing / stale) plus
   a JSON report under `artifacts/repro_lock_coverage_audit/<ts>/`.
   Exit code 0 = all present, 1 = at least one missing, plus a
   stderr warning for stale locks (older than
   `REPRO_LOCK_STALE_THRESHOLD_DAYS`, default 30).

2. For each missing row, regenerate the lock alongside its existing
   artifact bundle:

   ```
   runbooks/scripts/backfill_repro_lock.sh \
       <gate-name> \
       <artifact_path> \
       '<verification command that re-derives the bundle>'
   ```

   The script writes a `repro.lock` conforming to
   `frankenengine.reproducibility.lock.v1`, with `source_commit`
   pinned to `git rev-parse HEAD` and the supplied
   verification command in `replay.command_sequence`. It refuses to
   clobber an existing lock unless `BACKFILL_REPRO_LOCK_OVERWRITE=1`.

3. Re-run the audit to confirm coverage, then re-run the matrix gate:

   ```
   runbooks/scripts/audit_repro_lock_coverage.sh
   ./scripts/run_claim_to_proof_matrix_gate.sh ci
   ```

### Stale-lock policy

The audit script flags any `repro.lock` whose file mtime is older
than `REPRO_LOCK_STALE_THRESHOLD_DAYS` (default 30) as `severity:
warning`. The matrix gate does not currently *reject* on stale
locks — that is a follow-up tightening tracked separately. Operators
should re-run the verification command to refresh the bundle when a
stale warning fires.

### Selftest

Both scripts ship a deterministic selftest using the in-tree fixture
matrix from `bd-cixqu.4.3`:

```
scripts/e2e/repro_lock_runbook_smoke.sh run
```

Smoke asserts (8 PASS in `run` mode):
1. Shell syntax + shellcheck clean.
2. `audit selftest` exits 0.
3. `audit json` emits the canonical schema.
4. `audit audit` (default mode) produces a structured summary on the
   real in-tree matrix.
5. `backfill` refuses to clobber without `BACKFILL_REPRO_LOCK_OVERWRITE=1`.
6. `backfill` writes a fresh schema-valid `repro.lock`.
7. The written lock satisfies the production validator.
8. The audit picks up the backfilled lock as `present` on the next
   pass.

### Artifacts

The audit emits to
`artifacts/repro_lock_coverage_audit/<timestamp>/`:

- `repro_lock_coverage_report.json` (schema:
  `franken-engine.repro-lock-coverage-audit.v1`).
- `repro_lock_coverage_summary.md` (operator-readable).

The backfill writes directly to `<bundle>/repro.lock` (no separate
artifact dir).

### Out of scope (tracked for follow-up)

- FrankenTUI panel surfacing the audit report — requires the
  `frankentui` integration which is not in this bead's scope.
- Hard rejection on stale locks (currently warning-only).
- `frankenctl repro verify --bundle <path>` integration — the
  current scripts are bash-side helpers; the Rust verifier integration
  lands separately.

## Production Feature Catalog

(Added by `bd-cixqu.6.7` — operator surface for the F.5 unified
production-feature catalog gate.)

### Schema overview

`docs/production_feature_catalog_v1.json` declares N (today: 3) named
production features. Each entry pairs a **canonical feature id** (e.g.
`signed_ifc_declassification_receipts`) with the source `FE-CLAIM-N`
row in `docs/claim_to_proof_matrix_v1.json` and the bundle requirements
the operator must satisfy before the feature can be claimed OBSERVED.

The on-disk sub-bundles live under
`artifacts/production_feature_catalog/<short-name>/<timestamp>/` and
each ship a `feature_catalog_manifest.json` conforming to
`franken-engine.production-feature-catalog-bundle.v1`. The short
bundle-dir names are different from the canonical feature ids:

| Canonical feature id                    | Bundle dir                                              | Source claim |
|---|---|---|
| `signed_ifc_declassification_receipts`  | `signed_ifc_declassification/`                          | FE-CLAIM-015 |
| `deterministic_replay_coverage`         | `deterministic_replay/`                                 | FE-CLAIM-013 |
| `red_team_compromise_rate_reduction`    | `red_team_compromise_rate/`                             | FE-CLAIM-011 |

The unified F.5 gate
(`scripts/run_rgc_production_feature_catalog.sh`) auto-detects the
latest sub-bundle per feature, validates each against the
sub-bundle schema, and emits
`production_feature_catalog_manifest.json` with **per-feature sha256
manifest hashes**. The matrix row `FE-CLAIM-014` is OBSERVED when all
three sub-bundles pass.

### When to refresh

Refresh a feature's bundle when:
- The underlying `FE-CLAIM-N` evidence has changed (e.g. a new
  reproducibility bundle landed under
  `artifacts/reproducibility_bundles/FE-CLAIM-N/`).
- The audit script flags a feature as `stale` (manifest mtime older
  than `FEATURE_CATALOG_STALE_THRESHOLD_DAYS`, default 30).
- The F.5 unified gate's verdict drops to `degraded` or `fail`.

### How to interpret a stale-bundle warning

`runbooks/scripts/audit_feature_catalog.sh` reports `freshness_status
= stale` when a sub-bundle's `feature_catalog_manifest.json` mtime is
older than the threshold. Stale is currently warning-only — the F.5
gate continues to admit the feature, but downstream
`FE-CLAIM-014`-derived claims should be treated as **provisional**
until the bundle is refreshed.

### How to remediate

```
# 1. Audit per-feature freshness:
runbooks/scripts/audit_feature_catalog.sh

# 2. Refresh a single feature (or ALL):
runbooks/scripts/refresh_feature_bundle.sh signed_ifc_declassification_receipts
runbooks/scripts/refresh_feature_bundle.sh ALL

# 3. Re-audit to confirm:
runbooks/scripts/audit_feature_catalog.sh
```

The refresh script regenerates the sub-bundle's
`feature_catalog_manifest.json` carrying forward the prior
`evidence_bundle_references` and `verification_commands` so the lift
from `FE-CLAIM-N` stays stable. It also re-runs the F.5 unified gate
at the end to confirm coverage. Idempotent: running it twice in
succession produces two timestamped sub-bundle dirs without
corrupting prior state.

### How to add a 4th or 5th named feature

1. Add a new entry to `docs/production_feature_catalog_v1.json`'s
   `features[]` array. Mandatory fields: `feature_id` (canonical,
   snake_case with descriptive suffix), `source_claim` (the parent
   `FE-CLAIM-N`), `operator_description`,
   `required_bundle_contents[]`, `impossible_in_node_bun`,
   `artifact_root`.
2. Bump `docs/production_feature_catalog_v1.json`'s
   `minimum_feature_count` if the policy requires the new feature
   to count toward the OBSERVED threshold.
3. Add the canonical id to the `FEATURE_IDS=(...)` array in
   `scripts/run_rgc_production_feature_catalog.sh` and add the
   canonical→bundle-dir translation case to:
   - `canonical_id_to_bundle_dirname()` in
     `runbooks/scripts/audit_feature_catalog.sh`.
   - `canonical_to_bundle_dirname()` in
     `runbooks/scripts/refresh_feature_bundle.sh`.
4. Ship the sub-bundle's first instance under
   `artifacts/production_feature_catalog/<new-short-name>/<ts>/`.
5. Re-run the F.5 gate to confirm.

### What "lift from FE-CLAIM-N" means

Each F.x sub-bundle (`F.2 → FE-CLAIM-015`, `F.3 → FE-CLAIM-013`,
`F.4 → FE-CLAIM-011`) packages the *existing* evidence of an
already-OBSERVED matrix row into the
`franken-engine.production-feature-catalog-bundle.v1` shape. The
catalog does NOT regenerate the underlying evidence; it packages it
so a downstream consumer (e.g. the GA-exit evidence pack) can
present a self-contained "three named features" artifact without
chasing the source `FE-CLAIM-N` bundle paths separately.

### Selftest

`scripts/e2e/feature_catalog_runbook_smoke.sh run` (8 PASS in `run`
mode) covers:
1. Shell syntax + shellcheck clean.
2. Audit selftest exits 0.
3. Audit json mode schema-valid + 3 features.
4. Audit run produces structured summary.
5. Refresh `--list` shows three canonical feature ids.
6. Refresh single-feature exits 0 and re-runs F.5 ci=pass.
7. Refresh ALL exits 0 and re-runs F.5 ci=pass.
8. Audit picks up refreshed bundles as `present` + within freshness
   threshold.

### Artifacts

- `runbooks/scripts/audit_feature_catalog.sh` emits to
  `artifacts/feature_catalog_audit/<timestamp>/` (JSON report +
  markdown summary).
- `runbooks/scripts/refresh_feature_bundle.sh` writes directly under
  `artifacts/production_feature_catalog/<short-name>/<new-ts>/`.

### Out of scope (tracked for follow-up)

- FrankenTUI panel surfacing per-feature freshness with one-click
  refresh — requires the `frankentui` integration which is not in
  this bead's scope.
- Hard rejection on stale bundles (currently warning-only).
- 4th and 5th named features beyond the F.1-declared three.

## Fleet Convergence SLO Gate

(Added by `bd-cixqu.2.2` — declared-SLO half of Track B's fleet
quarantine convergence promotion.)

### What it gates

`scripts/run_rgc_fleet_convergence_slo_gate.sh` validates the
declared convergence SLO contract at
`docs/fleet_convergence_slo_v1.json` against the B.1 fleet harness
surface (`crates/franken-engine/tests/fleet_convergence_harness_integration.rs`
+ `crates/franken-engine/src/fleet_simulator.rs` +
`crates/franken-engine/src/fleet_immune_protocol.rs`).

The SLO contract declares, per partition profile:

- `partition_profile` (one of `normal`, `degraded`, `healing`)
- `fleet_size_nodes`
- `target_convergence_percentile` (e.g. `0.99`)
- `target_convergence_wall_time_seconds`
- `max_acceptable_drop_rate`

Plus an `unsupported_profiles` map declaring why
`permanent_split` and `split_brain` are refused (covered by
bd-cixqu.2.6's `partition` mode below).

### Modes

- `ci` — SLO contract schema validation + B.1 harness file
  cross-reference + per-secondary-SLO validation +
  unsupported-profile coverage. Does not invoke cargo; consumers
  that want live percentile measurements run the harness
  separately via rch. **Default and recommended for CI.**
- `partition` — bd-cixqu.2.6 legacy lane. Invokes the
  `convergence_slo_gate_test` cargo bin against
  `docs/fleet_partition_fault_profiles_v1.json`, asserting
  permanent_split / split_brain refuse and normal / degraded /
  healing admit.
- `selftest` — shape-only contract validation; no cargo, usable
  pre-rch.

### How to add a new partition profile

1. Append to `docs/fleet_convergence_slo_v1.json.secondary_slos[]`
   with all five SLO fields plus a `rationale` string.
2. Re-run `./scripts/run_rgc_fleet_convergence_slo_gate.sh ci`. The
   layer-3 per-secondary-SLO validator must accept the new entry.

### Selecting a partition profile (bd-cixqu.2.4 chaos vectors)

The gate's `ci` mode honours `FLEET_CONVERGENCE_SLO_PROFILE=<name>` to
pick a specific profile from
`docs/fleet_partition_fault_profiles_v1.json` instead of the SLO
contract's primary profile. The selected profile name + source +
chaos_vector (if any) is recorded under `partition_profile_used` /
`partition_profile_source` / `partition_profile_chaos_vector` in the
emitted manifest.

If the selected profile declares `gate_verdict:
"convergence-impossible"` (today: `permanent_split` + `split_brain`),
the `ci` verdict is overridden from `pass` to `convergence-impossible`
so a permanent-partition selection produces an honest verdict rather
than a silent admission. Two new chaos vectors landed under
`bd-cixqu.2.4`:

- `repeated_short_partitions` — intermittent 30s cycle with 8s
  partition windows; convergence required.
- `message_loss_without_partition` — uniform 25% message drop on a
  full mesh; convergence required.

Example operator invocations:

```
# default — uses SLO contract primary profile (normal)
./scripts/run_rgc_fleet_convergence_slo_gate.sh ci

# explicitly run the intermittent-partition chaos vector
FLEET_CONVERGENCE_SLO_PROFILE=repeated_short_partitions \
  ./scripts/run_rgc_fleet_convergence_slo_gate.sh ci

# expect convergence-impossible verdict on permanent partition
FLEET_CONVERGENCE_SLO_PROFILE=permanent_split \
  ./scripts/run_rgc_fleet_convergence_slo_gate.sh ci
# -> manifest.verdict = "convergence-impossible"
```

### How to mark a profile as unsupported

Append to `docs/fleet_convergence_slo_v1.json.unsupported_profiles`
with a string value explaining why (the gate's layer-4 check pins
the canonical set `{"permanent_split", "split_brain"}`; widening
that set requires editing both the SLO contract and the gate's
layer-4 comparison).

### Replay

`scripts/e2e/rgc_fleet_convergence_slo_replay.sh ci` re-runs the
gate against the latest (or pinned via
`RGC_FLEET_CONVERGENCE_SLO_REPLAY_RUN_DIR`) source bundle and
compares verdict + primary SLO. Exit codes: 0 = match, 1 = no
source bundle, 2 = bundle invalid, 3 = verdict mismatch, 4 =
primary-SLO field mismatch.

### Verification

- `./scripts/run_rgc_fleet_convergence_slo_gate.sh selftest`: PASS.
- `./scripts/run_rgc_fleet_convergence_slo_gate.sh ci`: verdict
  `pass`, primary SLO matches contract, secondary SLOs validated
  (2/2 currently).
- `./scripts/e2e/rgc_fleet_convergence_slo_replay.sh ci`: exit 0
  (verdict + primary SLO match between source and replay).
- `shellcheck -x -e SC2016,SC2155` on both scripts: clean.

### Out of scope (tracked for follow-up)

- Live percentile measurement integration with the B.1 harness via
  cargo test — gate currently validates the *contract* only; the
  *measured* percentile feed will be wired by a follow-up bead that
  parses the harness JSON output.
- Matrix promotion of FE-CLAIM-005 from TARGETED to OBSERVED —
  blocked on bd-cixqu.2.3 (de-escalation primitive, which is in
  turn blocked on bd-cixqu.1.3 TEE).

## Privacy-Preserving Fleet Learning Gate

`bd-cixqu.20.4` — Gate run_rgc_privacy_preserving_fleet_learning.sh + replay

Three-layer privacy-preserving fleet learning implementation combining:
1. **Federated Posterior Aggregation** (T.1): Individual node contributions hidden via weighted aggregation
2. **Differential Privacy** (T.2): (ε,δ)-noise injection protects against reconstruction attacks
3. **Secure Aggregation** (T.3): Cryptographic masking ensures aggregator sees only the sum

**Privacy Guarantees:**
- Individual peer contribution contents are cryptographically protected
- Only aggregate fleet-wide posteriors are revealed to coordinators  
- Privacy budget tracking prevents excessive information disclosure
- Logging discipline ensures no individual peer data appears in logs

**Artifacts Generated:**
- Privacy audit manifest with ε,δ budget consumption
- Cryptographic aggregation proof (count only, no individual content)
- Signed evidence bundle demonstrating three-layer protection
- Per-peer contribution evidence (participation count, not values)

**Components Tested:**
- `crates/franken-engine/src/federated_posterior_aggregation.rs`
- `crates/franken-engine/src/differential_privacy_posterior.rs` 
- `crates/dp/` (Bonawitz 2017 secure aggregation primitive)
- Integration test: `privacy_preserving_fleet_learning_integration.rs`

**Usage:**
```bash
# Standard CI validation
./scripts/run_rgc_privacy_preserving_fleet_learning.sh ci

# Individual component testing  
./scripts/run_rgc_privacy_preserving_fleet_learning.sh test

# Privacy-aware clippy (ensures no data leaks in lint output)
./scripts/run_rgc_privacy_preserving_fleet_learning.sh clippy
```

**Replay:**
`scripts/e2e/rgc_privacy_preserving_fleet_learning_replay.sh ci` validates 
the complete privacy-preserving workflow against the latest run artifacts.

**Privacy Logging Discipline:**
This gate follows bd-cixqu.45 logging requirements with privacy-specific carveouts:
- ✅ Log: participation counts, privacy budget consumption, aggregate results
- ❌ Never log: individual peer posteriors, confidence levels, node-specific risk data

## Sibling-repo integration verification

Track M (`bd-cixqu.13`) verifies that FrankenEngine still integrates cleanly
with each sibling repository it reuses, while holding a pinned commit per
sibling so a silent upstream regression cannot flow into our build. M.4
(`bd-cixqu.13.4`) is the operator surface for that posture.

**Source of truth.** The deterministic core lives in
`crates/franken-engine/src/sibling_repo_verification.rs`. The two runbook
scripts and the SHA-pin table mirror it; the JSON they emit conforms to
`franken-engine.sibling-repo-health.v1`.

### Per-sibling pass / skip / fail semantics

Each pinned sibling resolves to exactly one verdict:

- **pass** — the local `/dp/<slug>` HEAD matches the pinned SHA (or the
  integration smoke passed against it). Non-blocking.
- **skip** — the sibling repository is not present locally / its integration is
  feature-gated off. Skips never block a release.
- **fail** — the local HEAD has drifted from the pin, or the integration smoke
  failed against the pinned SHA. **Blocking**: a single `fail` marks the fleet
  view `DEGRADED`.

### SHA-pin governance

The pinned commit for every sibling lives in the table under *Sibling
Repository SHA Pinning* in
[`docs/CROSS_REPO_DEPENDENCY_ISOLATION_V1.md`](../CROSS_REPO_DEPENDENCY_ISOLATION_V1.md).
The pin is the safety lever: if a sibling's `main` branch breaks our
integration, the pin holds us at the last-passed SHA. SHAs are validated as
`^[a-f0-9]{7,40}$`.

To list current status (plain English + JSON, and a written artifact under
`artifacts/sibling_repo_health/<ts>/`):

```bash
runbooks/scripts/sibling_status.sh          # summary + artifact
runbooks/scripts/sibling_status.sh json     # JSON only (pipe-friendly)
runbooks/scripts/sibling_status.sh selftest # deterministic fixture self-test
```

### How to update a pinned SHA

Never hand-edit the pin table directly. Use the governed update, which (a)
records the prior pin in the append-only audit ledger
(`artifacts/sibling_repo_health/ledger.json`), (b) reruns the integration smoke
against the new SHA, and (c) writes the new SHA into
`CROSS_REPO_DEPENDENCY_ISOLATION_V1.md` **only if the smoke passes**:

```bash
# Advance the frankentui pin; smoke gates the commit.
runbooks/scripts/sibling_pin_update.sh frankentui <new_sha>

# Override the smoke command (default: ./scripts/test_standalone_build.sh ci):
SMOKE_CMD='cargo test -p frankenengine-engine --no-default-features' \
  runbooks/scripts/sibling_pin_update.sh frankensqlite <new_sha>
```

On smoke failure the script exits non-zero, the doc is left untouched (the pin
holds), and the held attempt is still recorded in the ledger for triage. After
a successful advance, commit the updated `CROSS_REPO_DEPENDENCY_ISOLATION_V1.md`
as part of the release cut.

### How to triage a cross-repo regression

1. Run `runbooks/scripts/sibling_status.sh` and read the `DEGRADED` summary —
   it names every `fail` sibling, its pinned vs local SHA, and the last-failed
   reason from the ledger.
2. For a drifted sibling, decide whether the upstream change is one we want.
   If yes, run `sibling_pin_update.sh <slug> <new_sha>`; the smoke must pass
   before the pin advances. If no, leave the pin held — that is the intended
   protection, not a bug.
3. Inspect the audit ledger (`artifacts/sibling_repo_health/ledger.json`) for
   the full pin history; each entry records prior SHA, new SHA, smoke outcome,
   whether it was committed, and a human note.
4. The frankentui "sibling-repo health" dashboard
   (`SiblingRepoHealthDashboard`) renders the same data as an aligned panel,
   with a per-sibling pin-advance count drawn from the ledger.

**Logging discipline (bd-cixqu.45).** Both scripts run under `set -euo
pipefail`, capture `commands.txt` (with `RUSTFLAGS` / `CARGO_INCREMENTAL` /
siblings root), and write the report and summary under
`artifacts/sibling_repo_health/<ts>/`. The Rust core emits a `SiblingLogEvent`
(`component=sibling_repo_verification`) per pin-update with a `committed` /
`held` outcome.

## Self-replacement lineage

Track V (`bd-cixqu.22`) delivers verified self-replacement lineage: a slot is
promoted from a delegate cell to successive native cells, each promotion bound
to a `ReplacementReceipt` carrying a translation-validation proof and a
pre-signed demotion fallback. V.6 (`bd-cixqu.22.6`) is the operator surface for
walking that lineage and reading a triggered demotion.

**Source of truth.** The receipt schema lives in
`crates/franken-engine/src/self_replacement.rs::ReplacementReceipt`; the
pre-signed fallback + its lifecycle live in
`crates/franken-engine/src/pre_signed_demotion_fallback.rs`
(`PreSignedDemotionFallback` / `FallbackStatus`). The two runbook scripts
mirror those types; the `self_replacement_lineage_replay` example
(`cargo run --example self_replacement_lineage_replay`, V.4) builds the same
`LineageChain` shape the scripts consume.

### How to read a ReplacementReceipt

Each receipt records one promotion step: `old_slot_id -> new_slot_id`, the old
and new cell digests, the `translation_validation_proof_ref` proving the new
cell preserves the old cell's observable behavior, the
`content_hash_chain_into_lineage` linking it to the prior step, the
`validation_artifacts` and their verdicts, the `rollback_token` (digest of the
last-known-good for reversal), the `promotion_rationale`, and the
`signature_bundle` that authorized it.

### How to walk the lineage chain across N replacements

Given a slot id and a serialized chain, walk every receipt in promotion order
and verify lineage integrity (each step's `old_cell_digest` must equal the
previous step's `new_cell_digest`; a mismatch is a broken link):

```bash
runbooks/scripts/walk_lineage.sh <slot_id> <lineage.json>          # walk + artifact
runbooks/scripts/walk_lineage.sh --json <slot_id> <lineage.json>   # JSON only (pipe-friendly)
runbooks/scripts/walk_lineage.sh selftest                          # deterministic in-tree self-test
```

The walk verdict is `ok` only when the chain is non-empty, every link is
intact, the queried slot terminates the chain, and every validation artifact is
approved. A `broken-linkage` verdict names the first step whose
`old_cell_digest` does not chain into its predecessor — the signal that a
receipt was tampered with or a step is missing. Output conforms to
`franken-engine.self-replacement-lineage.v1`.

### How to interpret a triggered demotion fallback receipt

When a promotion is rolled back, inspect the demotion-fallback bundle to surface
the original promotion receipt, the pre-signed demotion fallback, the trigger
that fired, and the post-demotion safe-mode state:

```bash
runbooks/scripts/inspect_demotion_receipt.sh <fallback.json>          # inspect + artifact
runbooks/scripts/inspect_demotion_receipt.sh --json <fallback.json>   # JSON only (pipe-friendly)
runbooks/scripts/inspect_demotion_receipt.sh selftest                 # deterministic in-tree self-test
```

Verdicts: `sealed` (fallback armed, no demotion fired), `active` (promotion
live), `demoted` (a *permitted* trigger fired — the expected rollback path),
`voided` (promotion succeeded, fallback retired). The fail-closed alarm is
**`ILLEGAL-TRIGGER`**: a demotion that fired on a trigger the fallback was not
sealed to honor (`DigestDrift`, `SeverityThresholdCrossed`,
`GatekeeperRejection`, `ManualOperator`). That is never expected and must be
escalated — it means a demotion was activated outside its sealed authority.
Output conforms to `franken-engine.demotion-fallback.v1`.

### When to manually halt promotion (operator override)

Operator override — manually halting a slot's promotion — is the safety valve.
Halt promotion when: `walk_lineage.sh` reports `broken-linkage` or
`unapproved-artifacts` for a slot; `inspect_demotion_receipt.sh` reports
`ILLEGAL-TRIGGER`; or a sibling/calibration gate is `DEGRADED` and the slot is
about to tier up. A manual halt is itself a `ManualOperator` demotion trigger,
so it flows through the same pre-signed-fallback path and lands the slot in its
recorded safe-mode state (typically `delegate_fallback_active`) — the operator
is never trusting a black box, and the override is itself an auditable receipt.

**Logging discipline (bd-cixqu.45).** Both scripts run under `set -euo
pipefail`, force `TZ=UTC` / `LC_ALL=C`, write a `commands.txt` plus the report
and summary under `artifacts/self_replacement_lineage/<ts>/` and
`artifacts/demotion_inspect/<ts>/`, and ship a deterministic `selftest` mode so
the parse + verdict logic is verifiable without an engine build.

## Limitations
