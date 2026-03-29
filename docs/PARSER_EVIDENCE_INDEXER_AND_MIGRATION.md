# Parser Evidence Indexer and Migration Pipeline

## Scope
`bd-2mds.1.9.5.2` adds a deterministic parser evidence index lane that links:

- run identity (`run_id`)
- artifact pointers (`run_manifest.json`, `events.jsonl`, `commands.txt`)
- replay command contract
- structured parser event rows (`trace_id`, `decision_id`, `policy_id`, component/event/outcome/error)

This lane is designed for cross-run forensic workflows and fail-closed schema upgrades.

## Module Surface
Implementation lives in:

- `crates/franken-engine/src/parser_evidence_indexer.rs`

Core capabilities:

- deterministic run/event indexing (`ParserEvidenceIndexBuilder`)
- schema boundary detection (`schema_migrations`)
- cross-run failure correlation (`correlate_regressions`)
- schema compatibility validation (`validate_event_schema_compatibility`)
- migration execution with receipts (`migrate_event_schemas`)

## Determinism Contract
Index output is deterministic for identical inputs:

- runs sorted by `run_id`
- events sorted by `(run_id, sequence, component, event)`
- correlation groups keyed by stable ordered tuples
- migration receipts sorted by `migration_id`

## Cross-Run Correlation
Correlation clusters are built from failure-oriented event rows where:

- `outcome == "fail"` or
- `error_code != null`

Grouping key:

- `component`
- `event`
- `scenario_id` (or fixture alias)
- `error_code`
- `outcome`

Only clusters observed in at least two distinct `run_id`s are reported.

## Schema Migration Pipeline
Schema versions must match `<family>.v<major>`.

Migration behavior:

1. Validate family compatibility (`from.family == to.family`).
2. Resolve migration path from current schema to target schema using declared steps.
   The currently traversed `from_schema` must resolve to exactly one declared next step; ambiguous duplicate source edges on the active path are rejected fail-closed.
   Every traversed migration step must also remain within that same schema family; cross-family intermediate hops are rejected fail-closed.
3. Apply steps in-order, emitting per-step receipts with affected record counts.
4. Recompute schema boundary diagnostics after upgrade.

No implicit migration path is allowed.

## Test Coverage
Integration tests:

- `crates/franken-engine/tests/parser_evidence_indexer.rs`

Module unit tests cover:

- schema parser validation
- deterministic build ordering
- repeated-failure cross-run clustering
- migration path validation and incompatibility failures
- migration application and receipt generation

## Gate Script
Run parser evidence indexer gate:

```bash
./scripts/run_parser_evidence_indexer.sh [check|test|clippy|ci]
```

The script enforces rch-backed heavy commands and emits deterministic artifacts under:

- `artifacts/parser_evidence_indexer/<timestamp>/run_manifest.json`
- `artifacts/parser_evidence_indexer/<timestamp>/events.jsonl`
- `artifacts/parser_evidence_indexer/<timestamp>/commands.txt`
