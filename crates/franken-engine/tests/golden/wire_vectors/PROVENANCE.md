# Golden File Provenance — `tests/golden/wire_vectors/` (versioned wire-format)

Companion to the canonical inventory at `tests/golden/PROVENANCE.md` and the
canonical-location decision in
[docs/operator-gates/GOLDEN_DIRECTORIES_RATIONALIZATION.md](../../../../../docs/operator-gates/GOLDEN_DIRECTORIES_RATIONALIZATION.md).

This directory holds **versioned wire-format vectors**: serialized payloads
of stable schemas (`*_v1.json`, `*_v1_wire.json`), text dumps of expected
dispatch arms, and per-feature reference snapshots. The shared character
across these files is that they pin the **on-wire / on-disk schema** rather
than a presentation format, so a schema reorder or content-hash change
trips an immediate diff.

This directory was migrated from `tests/golden_vectors/` to its current
canonical location at `tests/golden/wire_vectors/` in bd-ub6x8.6.3
(parent: bd-ub6x8.6).

## Regeneration

All franken-engine golden tests honor the project-wide `UPDATE_GOLDENS=1`
contract (bd-ub6x8.2):

```bash
UPDATE_GOLDENS=1 cargo test
```

Per-suite invocations are listed beside each fixture below.

The `.actual` siblings produced by failing runs are gitignored at the
crate-test root.

## Fixtures

### `frir_artifact_golden__frir_artifact_json_matches_golden.snap` *(moved to `tests/snapshots/` — bd-ub6x8.21.3)*

- **Owning test:** `tests/frir_artifact_golden.rs`. Migrated from
  `golden_diag::GoldenDiag` to `insta::assert_snapshot!` in bd-ub6x8.21
  child bead `bd-ub6x8.21.3`. The load-bearing fixture now lives at
  `tests/snapshots/frir_artifact_golden__frir_artifact_json_matches_golden.snap`.
- **Subject under test:** FRIR replay-artifact wire format v1.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --test frir_artifact_golden`,
  followed by `cargo insta review` for interactive blessing. The legacy
  `tests/golden/wire_vectors/frir_artifact_v1.json` file is retained for audit
  history until an explicit deletion/move approval is given.

### `optimal_stopping_certificate_golden__optimal_stopping_certificate_json_matches_golden.snap` *(moved to `tests/snapshots/` — bd-ub6x8.21.4)*

- **Owning test:** `tests/optimal_stopping_certificate_golden.rs`. Migrated
  from `golden_diag::GoldenDiag` to `insta::assert_snapshot!` in bd-ub6x8.21
  child bead `bd-ub6x8.21.4`. The load-bearing fixture now lives at
  `tests/snapshots/optimal_stopping_certificate_golden__optimal_stopping_certificate_json_matches_golden.snap`.
- **Subject under test:** optimal-stopping certificate wire format v1.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --test optimal_stopping_certificate_golden`,
  followed by `cargo insta review` for interactive blessing. The legacy
  `tests/golden/wire_vectors/optimal_stopping_certificate_v1.json` file is
  retained for audit history until an explicit deletion/move approval is given.

### `baseline_malformed_dispatch_golden__baseline_malformed_dispatch_fail_closed.snap` *(moved to `tests/snapshots/` — bd-ub6x8.21)*

- **Owning test:** `tests/baseline_malformed_dispatch_golden.rs`.
  Migrated from the embedded `EXPECTED` include of
  `tests/golden/wire_vectors/baseline_malformed_dispatch_fail_closed.json`
  to `insta::assert_snapshot!`.
- **Subject under test:** malformed baseline-interpreter dispatch inputs,
  including fail-closed binding-kind and UTF-16 boundary behavior.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --test baseline_malformed_dispatch_golden`,
  followed by `cargo insta review` for interactive blessing.
- **Legacy audit fixture retained:**
  `tests/golden/wire_vectors/baseline_malformed_dispatch_fail_closed.json`
  remains on disk until explicit deletion/move approval is given.

### `baseline_interpreter_conformance__baseline_dispatch_arm_snapshot.snap` *(moved to `tests/snapshots/` — bd-ub6x8.21)*

- **Owning test:** `tests/baseline_interpreter_conformance.rs`.
  Migrated from the embedded `DISPATCH_ARMS_GOLDEN` include of
  `tests/golden/wire_vectors/baseline_dispatch_arms.txt` to
  `insta::assert_snapshot!`.
- **Subject under test:** baseline-interpreter dispatch arm enumeration
  (text), including total, unique, and duplicate-count invariants.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --test baseline_interpreter_conformance baseline_dispatch_arm_snapshot_matches_golden -- --nocapture`,
  followed by `cargo insta review` for interactive blessing.
- **Legacy audit fixture retained:**
  `tests/golden/wire_vectors/baseline_dispatch_arms.txt` remains on disk until
  explicit deletion/move approval is given.

### `benchmark_runtime_diagnostics_snapshot__benchmark_and_runtime_diagnostics_outputs_match_golden.snap` *(moved to `tests/snapshots/` — bd-ub6x8.21)*

- **Owning test:** `tests/benchmark_runtime_diagnostics_snapshot.rs`.
- **Subject under test:** combined benchmark-evidence bundle report and
  runtime-diagnostics output snapshot for the diagnostics wire surface.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --test benchmark_runtime_diagnostics_snapshot`,
  followed by `cargo insta review` for interactive blessing. The legacy
  `tests/golden/wire_vectors/benchmark_diagnostics_output_v1.json` file is
  retained for audit history until an explicit deletion/move approval is given.

### `deterministic_serde.json`

- **Owning test:** invoked by the canonical-serde test suite; the
  fixture pins a representative `CanonicalValue` shape and its
  serialized form so a future encoding change is caught instantly.
- **Regen:** the file is hand-authored; rebless by re-running the
  owning suite with `UPDATE_GOLDENS=1` if the schema intentionally
  changes.

### `extension_host_lifecycle_integration__authority_decision_sequence.snap` *(moved to `tests/snapshots/` — bd-ub6x8.21)*

- **Owning test:** `tests/extension_host_lifecycle_integration.rs`.
  Migrated from the embedded include of
  `tests/golden/wire_vectors/extension_host_lifecycle_authority_decisions.json`
  to `insta::assert_snapshot!`.
- **Subject under test:** extension-host lifecycle authority decision
  ledger format.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --test extension_host_lifecycle_integration authority_decision_sequence_matches_golden_snapshot -- --nocapture`,
  followed by `cargo insta review` for interactive blessing.
- **Legacy audit fixture retained:**
  `tests/golden/wire_vectors/extension_host_lifecycle_authority_decisions.json`
  remains on disk until explicit deletion/move approval is given.

### `revocation_check_event_schema.json`, `revocation_check_event_v1_wire.json`, `signed_revocation_check_event_v1_wire.json`

- **Owning test:** `tests/revocation_enforcement_integration.rs`.
- **Subject under test:** revocation-event schema + the unsigned and
  signed wire representations.
- **Regen:**
  `UPDATE_GOLDENS=1 cargo test -p frankenengine-engine --test revocation_enforcement_integration`

### `semantic_flattening_inventory_golden__semantic_flattening_inventory_hashes.snap` *(moved to `tests/snapshots/` — bd-ub6x8.21)*

- **Owning test:** `tests/semantic_flattening_inventory_golden.rs`.
  Migrated from the embedded `EXPECTED` include of
  `tests/golden/wire_vectors/semantic_flattening_inventory_hashes_v1.json`
  to `insta::assert_snapshot!`; the test still decodes the serialized
  JSON and checks per-occurrence hash stability after the snapshot assertion.
- **Subject under test:** semantic-flattening inventory hash table —
  any drift in the canonical flattening yields a different inventory
  hash and the golden trips.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --test semantic_flattening_inventory_golden`,
  followed by `cargo insta review` for interactive blessing.
- **Legacy audit fixture retained:**
  `tests/golden/wire_vectors/semantic_flattening_inventory_hashes_v1.json`
  remains on disk until explicit deletion/move approval is given.

### `seqlock_fastpath_golden__seqlock_fastpath_recovery_surface.snap` *(moved to `tests/snapshots/` — bd-ub6x8.21)*

- **Owning test:** `tests/seqlock_fastpath_golden.rs`. Migrated from the
  embedded `EXPECTED` include of
  `tests/golden/wire_vectors/seqlock_fastpath_recovery_surface.json` to
  `insta::assert_snapshot!`.
- **Subject under test:** seqlock-fastpath recovery surface — the
  observable state after the seqlock fast-path retry contract fires.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --test seqlock_fastpath_golden`,
  followed by `cargo insta review` for interactive blessing.
- **Legacy audit fixture retained:**
  `tests/golden/wire_vectors/seqlock_fastpath_recovery_surface.json` remains
  on disk until explicit deletion/move approval is given.

### `test262_runner_conformance_golden__test262_runner_accounting.snap` *(moved to `tests/snapshots/` — bd-ub6x8.21)*

- **Owning test:** `tests/test262_runner_conformance_golden.rs`. Migrated
  from the embedded `EXPECTED` include of
  `tests/golden/wire_vectors/test262_runner_accounting_v1.json` to
  `insta::assert_snapshot!`.
- **Subject under test:** test262 conformance-runner accounting wire
  format v1.
- **Regen:**
  `INSTA_UPDATE=always cargo test -p frankenengine-engine --test test262_runner_conformance_golden`,
  followed by `cargo insta review` for interactive blessing.
- **Legacy audit fixture retained:**
  `tests/golden/wire_vectors/test262_runner_accounting_v1.json` remains on
  disk until explicit deletion/move approval is given.

## Toolchain

- Rust: 2024 edition
- frankenengine-engine: v0.1.0
- Mode: `UPDATE_GOLDENS=1` for blessing; default compare mode otherwise.
