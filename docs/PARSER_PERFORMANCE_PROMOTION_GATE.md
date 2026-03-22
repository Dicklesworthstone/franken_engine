# Parser Performance Promotion Gate (`bd-2mds.1.8.3`)

This contract defines the deterministic parser performance promotion gate for
PSRP-08 readiness.

## Scope

This lane is implemented by:

- `docs/PARSER_PERFORMANCE_PROMOTION_GATE.md`
- `crates/franken-engine/tests/fixtures/parser_performance_promotion_gate_v1.json`
- `crates/franken-engine/tests/parser_performance_promotion_gate.rs`
- `scripts/run_parser_performance_promotion_gate.sh`
- `scripts/e2e/parser_performance_promotion_gate_replay.sh`

## Contract Version

- `schema_version`: `franken-engine.parser-performance-promotion-gate.v1`
- `gate_version`: `1.0.0`

## Promotion Policy

Promotion is fail-closed.

The gate emits:

- `promote`: declared quantile wins versus all required peers are reproducible,
  confidence-bounded, and evidence-complete.
- `hold`: any required quantile win is missing, below threshold,
  confidence-inconclusive, protocol-drifted, or lacks telemetry evidence.

## Benchmark Protocol Requirements

The gate requires benchmark rows with deterministic protocol metadata:

- `workload_id`
- `corpus_id`
- `peer_id`
- `quantile`
- `franken_score_millionths`
- `peer_score_millionths`
- `sample_count`
- `confidence_low_delta_millionths`
- `confidence_high_delta_millionths`
- `protocol_hash`

Required peers and quantiles must be declared in the fixture contract.

## Reproducibility and Confidence Semantics

For every required `(peer_id, quantile)` pair:

1. improvement delta must meet or exceed the declared threshold,
2. confidence interval must be valid (`low <= high`),
3. confidence lower bound must remain strictly positive,
4. sample count must be non-zero,
5. row protocol hash must match the declared gate protocol hash.

A protocol hash mismatch is a hard blocker (`protocol_drift`).
A non-positive confidence lower bound is a hard blocker
(`non_reproducible_win`).

## Evidence Requirements

Mandatory evidence lanes must be `pass`:

- `cross_arch_matrix`
- `correctness_promotion`
- `regression_scoreboard`

Mandatory telemetry artifacts must be present and reproducible:

- `artifact_id`
- `manifest_path`
- `protocol_hash`
- `reproducible`

Any missing lane or non-reproducible telemetry artifact blocks promotion.

## Structured Log Contract

Each gate decision event must include:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`
- `blocked_pairs`
- `failing_workload_ids`
- `corpus_inventory`
- `quantile_inventory`
- `replay_pointers`

## Deterministic Replay Contract

One-command replay wrapper:

```bash
./scripts/e2e/parser_performance_promotion_gate_replay.sh
```

## Deterministic Execution Contract

All heavy Rust checks/tests for this lane run through `rch`.

The gate defaults remote builds into a repo-local, namespaced target directory
(`target_rch_parser_performance_promotion_gate_<mode>_<pid>`) so remote workers
do not depend on fragile `/tmp`-backed incremental state.

Fail-closed `rch` policy:

- local fallback signatures (`running locally`, `falling back to local`,
  `RCH-E326`, dependency-preflight fallback) are hard failures.
- artifact retrieval failures (`Artifact retrieval failed`, rsync code-23
  retrieval errors) are hard failures.
- missing remote-exit markers are hard failures.
- only remote `exit=0` paired with explicit artifact-timeout signatures is
  treated as recoverable (manifest remains fail-closed on any other ambiguity).
- non-recoverable transport, timeout, or cancellation paths surface directly in
  `failed_command` as `(rch-exit=<code>)`, `(remote-exit=<code>)`, or
  `(timeout-<N>s)` so operators can distinguish them from compiler diagnostics.

Canonical command:

```bash
./scripts/run_parser_performance_promotion_gate.sh ci
```

Pinned operator verify target example:

```bash
CARGO_TARGET_DIR=$PWD/target_rch_parser_performance_promotion_gate_verify \
  ./scripts/run_parser_performance_promotion_gate.sh ci
```

Modes:

- `check`: compile focused performance-gate tests
- `test`: run focused performance-gate tests
- `clippy`: lint focused target with `-D warnings`
- `ci`: check + test + clippy

## Required Artifacts

Each run emits:

- `artifacts/parser_performance_promotion_gate/<timestamp>/run_manifest.json`
- `artifacts/parser_performance_promotion_gate/<timestamp>/events.jsonl`
- `artifacts/parser_performance_promotion_gate/<timestamp>/commands.txt`
- `artifacts/parser_performance_promotion_gate/<timestamp>/step_logs/step_*.log`

Manifest includes gate mode, deterministic replay command, benchmark protocol
hash, blocked pair inventory, deterministic environment fingerprint fields,
and pass/fail outcome.

## Operator Verification

```bash
CARGO_TARGET_DIR=$PWD/target_rch_parser_performance_promotion_gate_verify \
  ./scripts/run_parser_performance_promotion_gate.sh ci
cat artifacts/parser_performance_promotion_gate/<timestamp>/run_manifest.json
cat artifacts/parser_performance_promotion_gate/<timestamp>/events.jsonl
cat artifacts/parser_performance_promotion_gate/<timestamp>/commands.txt
cat artifacts/parser_performance_promotion_gate/<timestamp>/step_logs/step_000.log
./scripts/e2e/parser_performance_promotion_gate_replay.sh
```
