# Mock Findings Delta - 2026-04-21

This pass re-scanned for explicit placeholders, simulated evidence, and disabled
`todo!()` / `unimplemented!()` coverage outside the files already listed in
`docs/audit/mock_findings_20260420.md`.

## Scope

- Read `AGENTS.md`, `README.md`, and the `mock-code-finder` skill guidance.
- Excluded the prior audited targets where possible, including the known
  baseline interpreter work and the 2026-04-20 mock findings list.
- Searched `crates/` and `scripts/` for placeholder comments, simulated
  artifacts, `todo!()`, `unimplemented!()`, and fake evidence patterns.
- Checked `.beads/issues.jsonl` for likely duplicates before creating new beads.

## New Beads

| Bead | Finding | Primary file | Why it matters |
| --- | --- | --- | --- |
| `bd-pzjan` | Replace simulated profiling artifacts in `run_profiling.sh` | `scripts/run_profiling.sh` | Missing `frankenctl` writes mock profile JSON and synthetic optimization recommendations that can look like real profiling evidence. |
| `bd-3c070` | Replace simulated fleet quarantine convergence evidence | `scripts/test_fleet_quarantine_e2e.sh` | The script writes hardcoded convergence percentiles and mock TEE verification artifacts after tests run, instead of deriving them from measured events. |
| `bd-voz7i` | Make event-loop E2E assert microtask and timer ordering | `scripts/test_event_loop.sh` | The test currently documents the expected `sync, micro, timer` order but only checks that `frankenctl run` exits successfully. |
| `bd-13kpi` | Implement Test262 regression gate high-water update mode | `scripts/test262_regression_gate.sh` | `update` mode is an explicit placeholder that prints intended behavior without running the runner or updating high-water marks. |
| `bd-1vih6` | Re-enable franken-core lowering pipeline closure regression | `crates/franken-core/src/lowering_pipeline.rs` | An ignored test is just `unimplemented!()`, leaving closure body lowering/CreateClosure behavior unasserted in franken-core. |

## Notes

- I did not create a duplicate bead for the franken-engine lowering pipeline
  placeholder already called out in the 2026-04-20 audit.
- I left broad, already-closed epics alone and created concrete follow-up bugs
  where a current file still emits fake artifacts or skips an assertion.
- This is an audit and planning delta only; no runtime code was changed in this
  commit.
