# Golden File Provenance — `tests/goldens/` (JSON) — DRAINING

Companion to the canonical inventory at `tests/golden/PROVENANCE.md` and the
canonical-location decision in
[docs/operator-gates/GOLDEN_DIRECTORIES_RATIONALIZATION.md](../../../../docs/operator-gates/GOLDEN_DIRECTORIES_RATIONALIZATION.md).

## Status

**Draining** (bd-ub6x8.6 + bd-ub6x8.6.2). Four of the original six
subdirectories migrated into `tests/golden/<feature>/`:

| Old path                                 | New path                                 | bead         |
|------------------------------------------|------------------------------------------|--------------|
| `tests/goldens/ir/`                      | `tests/golden/ir/`                       | bd-ub6x8.6.2 |
| `tests/goldens/evidence/`                | `tests/golden/evidence_bundle/`          | bd-ub6x8.6.2 |
| `tests/goldens/react_compilation/`       | `tests/golden/react_compilation/`        | bd-ub6x8.6.2 |
| `tests/goldens/benchmark_diagnostic/`    | `tests/golden/benchmark_diagnostic/`     | bd-ub6x8.6.2 |
| `tests/golden_tests/` (sibling root)     | `tests/golden/cli/`                      | bd-ub6x8.6.2 |
| `tests/golden_vectors/` (sibling root)   | `tests/golden/wire_vectors/`             | bd-ub6x8.6.3 |

The remaining two subdirectories below stay here until their owning tests
are no longer held exclusively by another agent (file reservations are
the gating signal); the migration is tracked by the parent bd-ub6x8.6.

## Regeneration

All franken-engine golden tests honor the project-wide `UPDATE_GOLDENS=1`
contract (bd-ub6x8.2). Workspace-wide:

```bash
UPDATE_GOLDENS=1 cargo test
```

Per-suite invocations are listed beside each subdirectory below.

The `.actual` siblings produced by failing runs are gitignored by
`crates/franken-engine/tests/.gitignore`; on a successful match each
helper sweeps them (bd-ub6x8.7).

---

## Subdirectory Fixtures

### `certificates/`

- **Owning test:** `tests/certificate_golden_tests.rs` (local
  `assert_golden` helper at L28; reads
  `tests/goldens/certificates/<test>.golden.json`).
- **Subject under test:** governance / capability certificate
  serialization, including mixed-verdict bundles.
- **Regen:**
  `UPDATE_GOLDENS=1 cargo test -p frankenengine-engine --test certificate_golden_tests`
- **Fixtures (7):** `certificate_bundle_mixed_verdicts.golden.json`,
  `certificate_evidence_basic.golden.json`,
  `certificate_evidence_memory.golden.json`,
  `certificate_evidence_network_io.golden.json`,
  `golden_workflow_test.golden.json`,
  `governance_receipt_comprehensive.golden.json`,
  `governance_receipt_denial.golden.json`,
  `timescale_certificate_insufficient.golden.json`.
- **Migration target (deferred):** `tests/golden/certificates/`
  (owning test held by BronzeHeron at the time of bd-ub6x8.6.2).

### `policy_theorem_compiler/`

- **Owning test:** `tests/policy_theorem_compiler_integration.rs`
  (`assert_policy_compiler_golden` helper at L129 and the
  `should_update_policy_goldens` gate at L118).
- **Subject under test:** policy theorem compiler outputs for valid
  policies, complex constraint sets, and explicit failure
  counterexamples.
- **Regen:**
  `UPDATE_GOLDENS=1 cargo test -p frankenengine-engine --test policy_theorem_compiler_integration`
- **Fixtures (3):** `valid_policy_all_passes.json`,
  `complex_constraints_all_passes.json`,
  `failure_counterexamples.json`.
- **Migration target (deferred):** `tests/golden/policy_theorem_compiler/`
  (owning test held by BronzeHeron at the time of bd-ub6x8.6.2).

## Toolchain

- Rust: 2024 edition
- frankenengine-engine: v0.1.0
- Mode: `UPDATE_GOLDENS=1` for blessing; default compare mode otherwise.
