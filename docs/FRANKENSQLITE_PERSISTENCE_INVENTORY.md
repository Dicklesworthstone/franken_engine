# FrankenEngine Frankensqlite Persistence Inventory

- Status: Active design inventory
- Owner track: Section 10.14 item 5 (`bd-1ps3`)
- Upstream ADR: `docs/adr/ADR-0004-frankensqlite-reuse-scope.md`
- Downstream consumers: `bd-89l2`, `bd-2d21`, 10.15 store implementations

## Scope

This document inventories current/planned FrankenEngine persistence needs and maps
each store to a `/dp/frankensqlite` integration point with explicit consistency,
retention, migration, and deterministic replay expectations.

## Database Topology

### Shared control-plane database (`control_plane.db`)

Use one shared control-plane database for indexes and caches that are tightly
coupled to governance/replay operations:

- replay index
- evidence index
- shadow evidence journal
- policy artifact cache
- IFC provenance index
- specialization index

### Isolated databases

Use isolated databases where write intensity, retention horizon, or audit posture
is materially different:

- `benchmark_ledger.db` for benchmark runs and score history
- `plas_witness.db` for PLAS witness artifacts
- `replacement_lineage.db` for replacement/promotion lineage artifacts

## Store Inventory

| Store | Model layer | Data model | Access pattern | Consistency requirement | Retention policy | Frankensqlite integration point | Migration strategy | Deterministic replay requirement |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| replay index | raw frankensqlite | run metadata + artifact pointers keyed by `trace_id`/`run_id` | write-on-run, query by trace/time/status | strong consistency for append and lookup | long-lived (audit window) | `frankensqlite::control_plane::replay_index` | additive columns + versioned views | required; replay manifests must resolve deterministically |
| evidence index | raw frankensqlite | evidence records keyed by `decision_id`/`policy_id`/`trace_id` | append-heavy, filtered reads for incident/audit | strong consistency and durable ordering | long-lived with legal/audit constraints | `frankensqlite::control_plane::evidence_index` | append-only schema evolution, no destructive rewrite | required; evidence linkage must replay identically |
| shadow evidence journal | sqlmodel_rust on frankensqlite | normalized source snapshots + advisory events + replay checkpoints keyed by monotonic `sequence_id` | append-heavy, filtered reads by bead/source/retention class | strong consistency for replay-stable sequence ordering and parent-link integrity | bounded windowed retention with checkpoint/audit preservation | `sqlmodel_rust::ShadowEvidenceJournalEntry` | additive typed fields + fail-closed import/export invariants | required; shadow-daemon advisory replay must reconstruct exact event ordering and retained checkpoints |
| benchmark ledger | raw frankensqlite | benchmark run summary + metric series + environment digest | bulk insert + range scans by profile/version | strong consistency for score publication | medium/long (release history + regression windows) | `frankensqlite::benchmark::ledger` | versioned metric columns + compatibility adapters | required for benchmark claim verification |
| policy artifact cache | raw frankensqlite | compiled policy blobs + schema hashes + validation status | read-mostly with controlled refresh writes | read-after-write consistency for policy rollout | bounded LRU + minimum epoch floor | `frankensqlite::control_plane::policy_cache` | explicit cache-version bump + warmup migration | required when policy decisions are replayed |
| PLAS witness store | sqlmodel_rust on frankensqlite | witness envelope + confidence bounds + artifact refs | append and query by subject/epoch | strong consistency on witness publication | medium/long, tied to calibration windows | `frankensqlite::analysis::plas_witness` | schema hash pinned, additive witness fields | required for capability decision replay |
| replacement lineage log | sqlmodel_rust on frankensqlite | slot promotion/demotion lineage + signed receipts | append-only + lineage walk by slot | append-only integrity + monotonic sequence | long-lived, never destructive delete | `frankensqlite::replacement::lineage_log` | append-only table family with compatibility views | required; promotion audits must reconstruct exactly |
| IFC provenance index | sqlmodel_rust on frankensqlite | label-flow provenance edges + declassification references | append + graph-style filtered retrieval | strong consistency for enforcement traceability | long-lived with compaction of redundant edges | `frankensqlite::control_plane::ifc_provenance` | additive edge metadata + index migrations | required for non-interference incident replay |
| specialization index | sqlmodel_rust on frankensqlite | proof-specialization mapping + invalidation markers | read-heavy, update on proof churn | read-after-write consistency for invalidation | medium retention with archived snapshots | `frankensqlite::control_plane::specialization_index` | epoch-aware migration with backfill checks | required; fallback/invalidation must replay deterministically |

## Decision Boundary: Shared Vs Isolated

Use an isolated database if one or more are true:

1. Data has materially different retention or legal/audit boundaries.
2. Write load can starve control-plane lookup paths.
3. Corruption blast radius must be constrained to one domain.

Otherwise prefer shared control-plane DB to reduce cross-store join complexity.

## Review Gate Requirements

Before implementing a new store:

1. Add/update inventory row in this document.
2. Declare whether the store is shared or isolated and why.
3. Set the `Model layer` (`raw frankensqlite` or `sqlmodel_rust on frankensqlite`) with rationale.
4. Map to a concrete frankensqlite integration point.
5. Document deterministic replay expectations.
6. For typed-schema-heavy stores, justify `frankensqlite` vs `sqlmodel_rust` per `bd-2d21`.

## Traceability Matrix (10.15)

- Witness workflows -> PLAS witness store
- Replacement/promotion workflows -> replacement lineage log
- Provenance/non-interference workflows -> IFC provenance index
- Proof specialization workflows -> specialization index
- Benchmark governance workflows -> benchmark ledger
- Replay/evidence governance workflows -> replay index + evidence index
- Shadow-daemon advisory workflows -> shadow evidence journal

## Operator Verification

- Confirm this inventory exists and includes all required stores:
  - `cargo test -p frankenengine-engine --test frankensqlite_persistence_inventory`
- Confirm releases include reuse/reimplement gate evidence:
  - `.github/PULL_REQUEST_TEMPLATE.md`
  - `docs/RELEASE_CHECKLIST.md`
