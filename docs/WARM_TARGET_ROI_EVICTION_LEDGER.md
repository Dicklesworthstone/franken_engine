# Warm Target ROI Eviction Ledger

`scripts/warm_target_roi_eviction_ledger.sh` decides whether a resident-proof
warm target should be retained, cooled, or evicted based on reuse value,
pressure, and incident history.

## Purpose

Sticky workers and reusable `CARGO_TARGET_DIR`s only help when locality is still
worth the pressure they impose. This ledger gives operators a deterministic,
bounded policy surface instead of leaving warm-target retention to intuition.

## Usage

```bash
./scripts/warm_target_roi_eviction_ledger.sh \
  --bundle-report-json artifacts/bundle_report.json \
  --sticky-plan-json artifacts/sticky_worker_warm_target_plan.json \
  --hotspot-ledger-json artifacts/sync_closure_hotspots.json \
  --pressure-snapshot-json artifacts/pressure_snapshot.json \
  --incident-history-json artifacts/incident_history.json \
  --output-dir /tmp/warm-target-roi
```

Required inputs:

- resident bundle report
- sticky warm-target plan
- sync-closure hotspot ledger
- pressure snapshot
- incident history snapshot

## Contract

The emitted `warm_target_roi_ledger.json` uses schema version
`franken-engine.warm-target-roi-eviction-ledger.v1`.

Key fields:

- `bundle_id`
- `worker_id`
- `target_dir`
- `decision`
- `recommended_action`
- `reason`
- `policy_findings[]`
- `roi.expected_reuse_score`
- `roi.realized_reuse_score`
- `roi.reuse_delta`
- `pressure_snapshot`
- `incident_summary`
- `upstream_summaries`
- `hash_basis`
- `artifact_paths`

## Decisions

- `retain`
  - `recommended_action`: `retain_warm_target`
  - exit code `0`
- `cool`
  - `recommended_action`: `cool_warm_target`
  - exit code `75`
- `evict`
  - `recommended_action`: `evict_warm_target`
  - exit code `42`

The current policy rules are:

- critical disk or memory pressure forces eviction
- repeated noisy incidents cool a target even when reuse value is nontrivial
- strong realized reuse under bounded pressure retains the target
- otherwise the target is evicted for low ROI

## Artifacts

Each run emits:

- `warm_target_roi_ledger.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

## Proof

The smoke harness is:

```bash
./scripts/e2e/warm_target_roi_eviction_ledger_smoke.sh check
./scripts/e2e/warm_target_roi_eviction_ledger_smoke.sh selftest
```

Required fixtures:

- high-ROI retain
- low-ROI evict
- disk-pressure forced eviction
- incident-history cooling
- repeated retain fixture proving stable ledger hashes
