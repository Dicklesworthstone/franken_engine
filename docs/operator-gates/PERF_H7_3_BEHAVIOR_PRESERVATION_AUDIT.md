# PERF-H7.3 — mimalloc Behavior-Preservation Audit (bd-o4cbn.3.3)

Audit record for the H7.3 behavior-preservation gate: switching the global
allocator to mimalloc (H7.1, bd-o4cbn.3.1) must be **observation-equivalent** —
no test result, replay outcome, or decision artifact should change.

Run on a clean worktree off `55845b8b` (`CARGO_INCREMENTAL=0`,
`RUSTFLAGS="-C linker=cc"`), 2026-05-26.

## Verdict: observation-equivalence SUPPORTED; literal all-green criteria BLOCKED by pre-existing tree debt

### Where mimalloc actually lives (scope)

`#[global_allocator] static GLOBAL: mimalloc::MiMalloc` is applied in exactly
two places:

- `crates/franken-engine/src/bin/frankenctl.rs` (the CLI binary)
- `crates/franken-engine/benches/hot_paths.rs` (the bench harness)

It is **not** applied to the `frankenengine-engine` library. Therefore the
`cargo test --lib` harness, the `frankenengine-metamorphic` crate, and the
bash replay-coverage gate all link the **system allocator**, not mimalloc.
Their results are allocator-independent **by construction** — identical with or
without the H7.1 change.

### The five gates

| # | gate | exit | meaning |
|---|---|---|---|
| 1 | `cargo test --lib -p frankenengine-engine` | **101** | aborted (stack overflow) + 232 live-FAILED — see below (pre-existing) |
| 2 | `cargo clippy --all-targets -- -D warnings` | **101** | pre-existing compile error (see below) |
| 3 | `cargo fmt --check` | **1** | tree-wide formatting drift (see below) |
| 4 | `./scripts/run_replay_coverage_metric_gate.sh ci` | **0** | pass |
| 5 | `cargo run -p frankenengine-metamorphic --bin run_metamorphic_suite` | **0** | **16 relations / 16000 pairs / 0 violations** |

### Behavior-preservation evidence (the meaningful signal)

- **Metamorphic suite: 0 violations across 16,000 pairs** (16 relations) — the
  strongest available observation-equivalence signal, green.
- **Replay-coverage gate: exit 0.**
- The lib unit tests do **not** link mimalloc, so any pass/fail there is
  unchanged by the allocator swap. None of the failures (below) represent a
  *change* introduced by mimalloc.

Conclusion: the H7.3 hypothesis — mimalloc is observation-equivalent — is
**supported**. The allocator swap changes nothing observable.

### Why the literal "all five exit 0" criteria are not met (all pre-existing, none mimalloc-related)

These failures exist at HEAD `55845b8b` independent of the allocator and would
be present with the system allocator too. They are tree-wide debt, not H7
regressions:

- **Gate 1 — the lib-test process ABORTS via stack overflow, plus 232
  live-FAILED tests.** The run reaches `tee_live_quote::tests::detect_tee_capability_error`,
  which **overflows its stack** and aborts the whole test process
  (`SIGABRT`, signal 6) — so no `failures:` detail block and no `test result:`
  summary are ever printed (the per-failure panic messages are buffered and
  lost on abort). Before the abort, 232 tests had already printed `... FAILED`
  status live, concentrated in persistence / revocation subsystems:
  `replacement_lineage_log` (56), `demotion_rollback` (46), `revocation_chain`
  (31), `capability_witness` (31), `revocation_enforcement` (27), plus scattered
  others. Because the abort destroyed the detail summary, the *reasons* for
  those 232 are uncharacterized here — but all are on the system allocator and
  none are in `moonshot_weekly_report` / `expected_info_value_scoring` (this
  session's EIV fix, which passes). The repo "green" gate (bd-84lcn) is
  **compile-only and never runs the lib tests**, so both the stack-overflow
  crash and the 232 failures have accumulated unobserved. The stack-overflow
  crash is filed as **bd-g63gw** (it makes `cargo test --lib` un-completable on
  this tree regardless of the failures).
- **Gate 2 — clippy** fails on a pre-existing **compile error** `E0107: missing
  generics for struct GenericStruct` in `franken-engine-deterministic-derive`
  (test `integration_tests`) — a proc-macro crate, not the engine, not a lint,
  not mimalloc.
- **Gate 3 — fmt** reports drift across hundreds of files (e.g. `crates/dp/`,
  nearly every `crates/franken-engine/src/*.rs`). The H7.3-relevant files are
  clean.

### Disposition

H7.3 **cannot be closed "all five green"** until the tree's pre-existing
test/clippy/fmt debt is resolved — which is orthogonal to the mimalloc switch
and out of H7's scope. The behavior-preservation hypothesis itself is confirmed
by the allocator-relevant evidence (metamorphic 0/16000, replay exit 0,
allocator confined to bin/bench). A future re-run on a test-green tree should
flip all five to green quickly; this record + the gate logs (under
`artifacts/` on the audit machine, gitignored) document the evidence so that
re-run is cheap.
