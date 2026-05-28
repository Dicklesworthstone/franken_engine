# Golden File Provenance — `tests/golden_vectors/` (versioned wire-format)

Companion to the canonical inventory at `tests/golden/PROVENANCE.md` and the
canonical-location decision in
[docs/operator-gates/GOLDEN_DIRECTORIES_RATIONALIZATION.md](../../../../docs/operator-gates/GOLDEN_DIRECTORIES_RATIONALIZATION.md).

This directory holds **versioned wire-format vectors**: serialized payloads
of stable schemas (`*_v1.json`, `*_v1_wire.json`), text dumps of expected
dispatch arms, and per-feature reference snapshots. The shared character
across these files is that they pin the **on-wire / on-disk schema** rather
than a presentation format, so a schema reorder or content-hash change
trips an immediate diff.

This directory is one of three legacy golden roots that pre-date the
canonical-location decision (bd-ub6x8.6); migration into
`tests/golden/wire_vectors/` is deferred to a follow-up bead.

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

### `frir_artifact_v1.json`

- **Owning test:** `tests/frir_artifact_golden.rs` (delegates to
  `tests/golden_diag.rs::GoldenDiag` after bd-ub6x8.3.1).
- **Subject under test:** FRIR replay-artifact wire format v1.
- **Regen:**
  `UPDATE_GOLDENS=1 cargo test -p frankenengine-engine --test frir_artifact_golden`

### `optimal_stopping_certificate_v1.json`

- **Owning test:** `tests/optimal_stopping_certificate_golden.rs`
  (delegates to `GoldenDiag` after bd-ub6x8.3.1).
- **Subject under test:** optimal-stopping certificate wire format v1.
- **Regen:**
  `UPDATE_GOLDENS=1 cargo test -p frankenengine-engine --test optimal_stopping_certificate_golden`

### `baseline_dispatch_arms.txt`, `baseline_malformed_dispatch_fail_closed.json`

- **Owning tests:** `tests/baseline_malformed_dispatch_golden.rs`,
  `tests/baseline_interpreter_conformance.rs`.
- **Subject under test:** baseline-interpreter dispatch arm enumeration
  (text) and malformed-dispatch fail-closed contract (JSON).
- **Regen:**
  `UPDATE_GOLDENS=1 cargo test -p frankenengine-engine --test baseline_malformed_dispatch_golden`
  and `... --test baseline_interpreter_conformance`.

### `benchmark_diagnostics_output_v1.json`

- **Owning test:** `tests/benchmark_runtime_diagnostics_snapshot.rs`.
- **Subject under test:** runtime-diagnostics snapshot wire format v1.
- **Regen:**
  `UPDATE_GOLDENS=1 cargo test -p frankenengine-engine --test benchmark_runtime_diagnostics_snapshot`

### `deterministic_serde.json`

- **Owning test:** invoked by the canonical-serde test suite; the
  fixture pins a representative `CanonicalValue` shape and its
  serialized form so a future encoding change is caught instantly.
- **Regen:** the file is hand-authored; rebless by re-running the
  owning suite with `UPDATE_GOLDENS=1` if the schema intentionally
  changes.

### `extension_host_lifecycle_authority_decisions.json`

- **Owning test:** `tests/extension_host_lifecycle_integration.rs`.
- **Subject under test:** extension-host lifecycle authority decision
  ledger format.
- **Regen:**
  `UPDATE_GOLDENS=1 cargo test -p frankenengine-engine --test extension_host_lifecycle_integration`

### `revocation_check_event_schema.json`, `revocation_check_event_v1_wire.json`, `signed_revocation_check_event_v1_wire.json`

- **Owning test:** `tests/revocation_enforcement_integration.rs`.
- **Subject under test:** revocation-event schema + the unsigned and
  signed wire representations.
- **Regen:**
  `UPDATE_GOLDENS=1 cargo test -p frankenengine-engine --test revocation_enforcement_integration`

### `semantic_flattening_inventory_hashes_v1.json`

- **Owning test:** `tests/semantic_flattening_inventory_golden.rs`.
- **Subject under test:** semantic-flattening inventory hash table —
  any drift in the canonical flattening yields a different inventory
  hash and the golden trips.
- **Regen:**
  `UPDATE_GOLDENS=1 cargo test -p frankenengine-engine --test semantic_flattening_inventory_golden`

### `seqlock_fastpath_recovery_surface.json`

- **Owning test:** `tests/seqlock_fastpath_golden.rs`.
- **Subject under test:** seqlock-fastpath recovery surface — the
  observable state after the seqlock fast-path retry contract fires.
- **Regen:**
  `UPDATE_GOLDENS=1 cargo test -p frankenengine-engine --test seqlock_fastpath_golden`

### `test262_runner_accounting_v1.json`

- **Owning test:** `tests/test262_runner_conformance_golden.rs`.
- **Subject under test:** test262 conformance-runner accounting wire
  format v1.
- **Regen:**
  `UPDATE_GOLDENS=1 cargo test -p frankenengine-engine --test test262_runner_conformance_golden`

## Toolchain

- Rust: 2024 edition
- frankenengine-engine: v0.1.0
- Mode: `UPDATE_GOLDENS=1` for blessing; default compare mode otherwise.
