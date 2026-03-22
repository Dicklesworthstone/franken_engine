# RGC Engine-Product Blocker Ledger V1

## Purpose

`bd-1lsy.5.10.2` turns the engine-side blocker model into a deterministic
artifact program that downstream `franken_node` and rollout work can consume
without reading source code or hand-assembling status from beads.

This acceptance layer is intentionally a wrapper around the existing
`engine_product_blocker_ledger` module, not a replacement for it. The core Rust
model stays in:

- `crates/franken-engine/src/engine_product_blocker_ledger.rs`

The acceptance layer adds:

- a small emission binary
- deterministic runner and replay wrappers
- a machine-readable contract for required outputs and failure modes
- focused integration tests for artifact generation and fail-closed behavior

## Inputs

The blocker-ledger bundle consumes three local truth sources:

1. `crates/franken-engine/src/engine_product_blocker_ledger.rs`
   The canonical engine-side blocker and cohort model plus default gate logic.
2. `docs/support_surface_contract.json`
   The engine-owned support boundary and downstream product-ready delegation
   rule.
3. `br list --all --json`
   A live bead snapshot used to enrich blocker routing with real assignees and
   current bead status.

The emission path is:

- `crates/franken-engine/src/bin/franken_engine_product_blocker_ledger.rs`

## Bundle Artifacts

The bundle emitted under `artifacts/rgc_engine_product_blocker_ledger/<timestamp>/`
must contain:

- `engine_product_blocker_ledger.json`
- `cohort_readiness_rollup.json`
- `owner_routing_report.json`
- `gate_report.json`
- `support_surface_contract.json`
- `beads_snapshot.json`
- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `trace_ids.json`
- `step_logs/`

The top-level ledger file stays compatible with downstream consumers that expect
plain `.version`, `.blockers`, and `.cohort_rollups` keys at the root. The
adjacent rollup and routing reports provide operator-facing summaries without
changing that root artifact shape.

## Gate Runner

Use the `rch`-backed gate runner:

```bash
./scripts/run_rgc_engine_product_blocker_ledger.sh ci
```

Supported modes:

- `bundle`
- `check`
- `test`
- `clippy`
- `ci`

Every CPU-intensive cargo step in this lane is executed through `rch`,
including the `cargo run` emission step.

## Failure Semantics

The lane fails closed when any of the following are true:

- `docs/support_surface_contract.json` is missing or invalid
- the support contract no longer delegates product-ready state to the
  franken-node handoff workflow
- the live bead snapshot is missing tracked blockers referenced by unresolved
  blocking or degraded entries
- unresolved blocking or degraded entries lose both owner and tracking-bead
  routing
- the emitted bundle is missing any required artifact

## Operator Verification

Representative verification commands:

```bash
jq empty docs/engine_product_blocker_ledger_v1.json

jq '.version, (.blockers | length), (.cohort_rollups | length)' \
  artifacts/.../engine_product_blocker_ledger.json

jq '.ready_or_advisory_count, .blocked_or_partial_count' \
  artifacts/.../cohort_readiness_rollup.json

jq '.orphaned_unresolved_count, (.routes | length)' \
  artifacts/.../owner_routing_report.json

jq '.verdict, .release_blocker_count, .ready_cohort_count' \
  artifacts/.../gate_report.json
```

## Replay Workflow

Use the replay wrapper to rerun the lane and print the latest complete bundle:

```bash
./scripts/e2e/rgc_engine_product_blocker_ledger_replay.sh show
```

The replay wrapper refuses incomplete newest directories and falls back to the
latest complete run directory instead. A complete replayable bundle now
requires:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `trace_ids.json`
- `engine_product_blocker_ledger.json`
- `cohort_readiness_rollup.json`
- `owner_routing_report.json`
- `gate_report.json`
- `support_surface_contract.json`
- `beads_snapshot.json`
- at least one `step_logs/step_*.log`

The wrapper prints the manifest, trace IDs, command transcript, gate report,
ledger, cohort rollup, owner-routing report, and the first step log so
operators can triage the latest valid run without manually spelunking the
artifact directory.
