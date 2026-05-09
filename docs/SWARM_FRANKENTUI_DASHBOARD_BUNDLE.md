# SWARM FrankenTUI Dashboard Bundle

Machine-readable contract: `docs/swarm_frankentui_dashboard_bundle_contract_v1.json`

Smoke gate: `scripts/e2e/swarm_frankentui_dashboard_bundle_smoke.sh`

Fixture cases: `scripts/testdata/swarm_frankentui_dashboard_bundle/cases.json`

The bundle records render-ready SWARM-OPS evidence for a future `/dp/frankentui`
view. It is not a TUI runtime and it is not an autonomous operator.

## Scope

`scripts/swarm_frankentui_dashboard_bundle.sh` consumes explicit JSON evidence
from the resource envelope, admission planner, stale recovery policy, RCH worker
truth ledger, proof-cache locality optimizer, and RCH rehabilitation ledger. It
may also consume `--snapshot-bundle-json` from
`scripts/swarm_live_readonly_snapshot_bundle.sh`. That optional bundle annotates
all panels with source freshness, fail-closed local fallback evidence, and
bd-eozx0/bd-x82vp provenance; it does not replace the required dashboard input
artifacts. It emits:

- `dashboard_bundle.json`
- `dashboard_events.ndjson`
- `events.jsonl`
- `commands.txt`
- `report.md`

The renderer contract names `/dp/frankentui` as the provider. `franken_engine`
only owns deterministic data adapters and fixtures for this lane.

## Panels

The bundle must always include these panel IDs:

- `capacity`
- `admitted_lanes`
- `stale_ownership`
- `rch_workers`
- `proof_cache_locality`
- `recovery_receipts`

Missing telemetry, stale ownership evidence, drained workers, blocked capacity,
and fail-closed upstream artifacts are visible display states. The adapter must
not omit a panel just because its source evidence is missing or stale.
When a live read-only snapshot bundle is supplied, every panel carries a
`live_readonly_snapshot` object so `/dp/frankentui` can render source freshness
and local fallback risk without inventing a second scheduler or resource
planner. If no snapshot bundle is supplied, the top-level `source_freshness`
section marks it `missing` without changing the legacy fixture decisions.

## Display States

Valid panel display states are:

- `healthy`
- `degraded`
- `missing`
- `stale`
- `blocked`
- `fail_closed`

Each panel includes a semantic theme token, focus order, tiny-layout support,
and an accessibility label so `/dp/frankentui` can render it without inventing
new engine-side UI semantics.

## Non-Mutation Policy

The adapter is fixture-fed and advisory-only. It does not query live Agent Mail,
change beads, release reservations, run Cargo, run RCH, mutate workers, change
queue policy, repair target directories, or write outside the requested output
directory.

Operator actions remain commands or notes in upstream evidence. The dashboard
bundle displays those actions as evidence; it does not execute them.
