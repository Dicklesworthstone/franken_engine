# Parser Parallel Interference and Parity Matrix Contract

This document defines the PSRP-05.4.2 contract for worker/seed parity-matrix
execution and adversarial determinism stress validation in:

- `crates/franken-engine/src/parallel_interference_gate.rs`
- `crates/franken-engine/src/parallel_parser.rs`

## Scope

- Execute deterministic parity matrices across worker-count and seed dimensions.
- Assert adversarial-profile stability and witness-diff explainability.
- Emit replayable, schema-stable gate artifacts for downstream correctness and
  cross-architecture gates.
- Fail closed on unresolved interference incidents or flake-rate violations.

## Matrix Dimensions

Baseline campaign dimensions for this lane:

- worker counts: `2`, `4`, `8`
- seeds: deterministic sequence `0..(seed_count-1)`
- repeats per seed: deterministic fixed count
- adversarial profiles:
  - operators-and-strings stress payloads
  - synthetic witness-diff mismatch explanation coverage

The gate runner records the active matrix profile in run-manifest metadata.

## Determinism and Drift-Explanation Contract

Each mismatch must remain diagnosable through structured evidence:

- interference class (`merge-order`, `scheduler`, `data-structure-iteration`,
  `artifact-pipeline`, `timeout-race`, `backpressure-drift`)
- severity (`info`, `warning`, `critical`)
- `(seed, worker_count, run_index)` coordinate
- expected/actual output witnesses
- triage hint + remediation playbook ID
- one-command replay pointer

Witness and transcript diffs are represented by `WitnessDiff` and transcript
comparison entries; operator summaries must rank root-cause hints by incident
frequency and severity.

## Replay and Escalation Hooks

Replay bundles must provide deterministic rerun material for every incident:

- failing seed set
- failing worker-count set
- replay command list

Rollback integration is fail-closed:

- `promote` resets rollback failure counter
- `hold`/`reject` increments failure counter
- threshold crossing triggers serial rollback posture

## Gate and Artifacts

Primary gate script:

```bash
./scripts/run_parser_parallel_interference_gate.sh ci
```

Artifacts are emitted under:

- `artifacts/parser_parallel_interference/<timestamp>/run_manifest.json`
- `artifacts/parser_parallel_interference/<timestamp>/events.jsonl`
- `artifacts/parser_parallel_interference/<timestamp>/commands.txt`
- `artifacts/parser_parallel_interference/<timestamp>/step-*.log`

The manifest includes deterministic environment fingerprinting and a one-command
replay entry suitable for PSRP-07.2 and PSRP-08.2 consumption.
Unless the caller explicitly sets `CARGO_TARGET_DIR`, the gate now uses a
run-scoped default target directory rooted at
`/var/tmp/rch_target_franken_engine_parser_parallel_interference/` so concurrent
`rch` jobs do not block indefinitely on a shared build-directory lock. The
manifest records both `cargo_target_dir` and `cargo_target_dir_strategy`.
Compile-only preflight for `check` mode now uses `cargo test --no-run`, and the
lint lane uses `clippy-driver` through the same no-run test compilation path.
That keeps the gate on `rch`'s longer test-timeout surface instead of the
shorter build/check timeout bucket.

`rch` execution is fail-closed for this gate: if daemon/toolchain errors trigger
local fallback signatures, the run is marked failed with
`rch-local-fallback-detected` command attribution.
The runner also fails closed when `rch` logs a non-zero remote exit marker even
if the outer shell command itself returned success, preventing silent
continuation after remote worker failures.
Timeout-policy drift is treated as blocker evidence: if the logged
`timeout_secs` value is lower than the requested build timeout, the manifest
records an `rch-timeout-mismatch-*` failure instead of continuing to later
steps.
Timeout paths preserve failure provenance: when remote compiler diagnostics are
present before timeout, the manifest marks the failed command as
`rch-timeout-after-remote-compile-failure` instead of a generic timeout.
