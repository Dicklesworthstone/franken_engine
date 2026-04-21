# Mock / Placeholder Audit - 2026-04-20

Scope: `crates/` and `scripts/`, excluding build outputs and lockfiles.

Method: followed the `mock-code-finder` skill with documentation-first review, targeted ripgrep scans for explicit markers and implementation macros, simulated-work searches, hardcoded-result searches, AST probes for trivial `todo!` / `unimplemented!` functions, and targeted duplicate checks through `br search`.

## Running Count

- Files scanned under `crates/` and `scripts/`: 3,414
- Explicit marker hits across `crates/` and `scripts/`: 205
- Explicit marker hits in source/script paths (`crates/*/src`, `scripts`): 147
- `todo!` / `unimplemented!` / placeholder panic hits in source/script paths: 15
- New beads created from this audit: 3
  - `bd-2cixp` - `scripts/run_reality_check_acceptance_e2e.sh:524`
  - `bd-wx1d2` - `crates/franken-engine/src/certified_rewrite_optimizer.rs:721`
  - `bd-27jaw` - `crates/franken-engine/src/production_hardening_exit_gate.rs:1124`

## Prioritized Findings

| Priority | File:Line | Type | Why it matters | Status |
|---|---:|---|---|---|
| P0 | `scripts/run_reality_check_acceptance_e2e.sh:524` | Simulated acceptance evidence | The script fabricates guardplane, fleet, benchmark, and Test262 artifacts, then records PASS based on generated files or module presence. This can make release evidence look stronger than actual execution. | New bead `bd-2cixp` |
| P0 | `crates/franken-engine/src/certified_rewrite_optimizer.rs:721` | Fake optimizer/certifier | Rule matching always returns `const_fold`, rewriting returns the original program, validation always succeeds, and certificates are placeholders. It can report certified optimization without transformation or proof. | New bead `bd-wx1d2` |
| P1 | `crates/franken-engine/src/production_hardening_exit_gate.rs:1124` | Hardcoded production readiness metrics | Validation helpers are explicitly stubbed for compilation and return fixed containment, fuzz, property, and metamorphic outcomes. Production readiness should be evidence-derived or fail closed. | New bead `bd-27jaw` |
| P1 | `crates/franken-engine/src/bin/franken_react_sidecar.rs:235` | Placeholder parser | React component discovery is simulated by checking for `function` and `return`, then emits a hardcoded `ExampleComponent`. This can mislead sidecar artifacts for React workflows. | Needs bead if not covered by React sidecar work |
| P1 | `scripts/run_memory_budget_e2e.sh:99` | Simulated e2e result | The runner creates Rust test code but does not execute it; it increments pass counters from expected outcomes. Memory-budget evidence should come from actual execution or fail closed. | Needs bead |
| P1 | `scripts/run_crypto_migration_e2e.sh:160` | Simulated crypto round-trip | The script embeds real round-trip code, then bypasses it and echoes a fixed success string. Crypto migration evidence must execute the program or fail closed. | Needs bead |
| P2 | `crates/franken-engine/tests/real_world_program_suite.rs:315` | Simulated integration execution | The real-world program suite returns expected output strings by program name instead of executing through FrankenEngine. Useful as a fixture, but unsafe as conformance evidence. | Needs classification or conversion |
| P2 | `crates/franken-engine/src/lowering_pipeline.rs:6331` | Incomplete lowering | Class expressions lower to `undefined` with a TODO for full lowering. User-visible JS semantics are missing unless fail-closed elsewhere. | Check against parser/lowering gap beads before filing |
| P2 | `crates/franken-engine/src/signature_preimage.rs:1294` | Ignored `unimplemented!` tests | Constant-time comparison tests are ignored after API drift. This is less severe because it is test-only and ignored, but it leaves crypto regression coverage absent. | Needs cleanup bead if no existing owner |
| P2 | `crates/franken-engine/src/tee_attestation_policy.rs:3935` | Ignored `unimplemented!` tests | TEE policy tests for expired quotes and high-impact attestation are ignored after API drift. Product code may be fine, but coverage is stale. | Needs cleanup bead if no existing owner |

## False Positives / Lower Priority Buckets

- `zero_placeholder_gate.rs`, `zero_placeholder_scan.rs`, `control_plane_mock_inventory.rs`, and related tests intentionally contain terms like placeholder/mock because they implement detection policy.
- Many `simulated_*` functions are explicit deterministic model or test-harness simulations, not fake product behavior by themselves.
- `ContentHash::compute(b"placeholder")` appears in several object builders as a temporary preimage before deriving a real hash; those need local review before being treated as bugs.
- Existing baseline interpreter TODOs are numerous and mostly known product-surface gaps. This audit did not create baseline beads because the backlog already contains several baseline review/fix beads and those are larger than a top-three placeholder cleanup pass.

## Commands Used

```bash
rg -n --hidden -S "\\b(TODO|FIXME|HACK|XXX|STUB|PLACEHOLDER|MOCK|DUMMY|FAKE|TEMPORARY)\\b|not implemented|Not Implemented" crates scripts -g '!target/**' -g '!**/*.lock'
rg -n --hidden -S "unimplemented!\\s*\\(|todo!\\s*\\(|panic!\\s*\\(\\s*\\\"[^\\\"]*(not implemented|TODO|stub|placeholder)" crates/*/src scripts -g '!target/**' -g '!**/*.lock'
rg -n --hidden -S "For now|placeholder|stubbed|hardcoded|actual measurement|actual benchmarking|simulate successful|simulated results|actual .*requires|would integrate" crates/franken-engine/src crates/franken-engine/tests scripts -g '!target/**' -g '!**/*.lock'
br search "certified rewrite placeholder" --format json
br search "production hardening placeholder" --format json
br search "react sidecar placeholder" --format json
br search "reality check acceptance simulated" --format json
```
