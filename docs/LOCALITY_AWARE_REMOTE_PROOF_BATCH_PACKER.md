# Locality-Aware Remote Proof Batch Packer

`scripts/locality_aware_remote_proof_batch_packer.sh` turns multiple resident
remote-proof bundles into one deterministic worker-aware batch plan.

## Purpose

The resident bundle executor, artifact mirror, and warm-target ROI ledgers each
optimize one proof suite at a time. This packer is the next control-plane step:
it decides when several suites should share one worker and warm target because
their closure roots overlap, and when they must split because fairness or
worker/target compatibility says they should.

The checker is planning-only and fixture-driven. It never runs Cargo, never
queries live `rch`, and never guesses missing worker or mirror evidence.

## Usage

```bash
./scripts/locality_aware_remote_proof_batch_packer.sh \
  --bundle-reports-json artifacts/resident/bundle_reports.json \
  --mirror-manifests-json artifacts/resident/mirror_manifests.json \
  --roi-ledgers-json artifacts/resident/roi_ledgers.json \
  --fairness-policy-json artifacts/resident/fairness_policy.json \
  --output-dir /tmp/locality-aware-batch-plan
```

Required upstream evidence:

- resident bundle reports:
  `franken-engine.resident-remote-proof-bundle.v1`
- artifact mirror receipts or manifest snapshots
- warm-target ROI ledgers:
  `franken-engine.warm-target-roi-eviction-ledger.v1`

## Batch Manifest Contract

The emitted `batch_manifest.json` uses schema version
`franken-engine.locality-aware-remote-proof-batch-plan.v1`.

Key fields:

- `batch_manifest_id`
- `packing_decision`
- `reason`
- `validation_errors[]`
- `fairness_policy`
- `split_reasons[]`
- `batches[]`
- `hash_basis`
- `artifact_paths`

Each `batches[]` entry records:

- `batch_id`
- `worker_id`
- `target_dir`
- `bundle_ids[]`
- `closure_roots[]`
- `shared_locality_score`
- `total_predicted_cost_units`
- `bundle_rows[]`

Each `bundle_rows[]` entry records:

- `bundle_id`
- `pack_order`
- `preferred_worker_id`
- `preferred_target_dir`
- `locality_reason`
- `fairness_reason`
- `mirror_manifest_hash`
- `retrieval_pack_artifact_count`
- `roi_decision`
- `roi_recommended_action`

## Split Semantics

The packer only splits for truthful reasons:

- `fairness_split:max_bundles_per_worker`
- `fairness_split:max_total_cost_per_worker`
- `compatibility_split:worker_or_target_incompatibility`

Missing mirror evidence, missing ROI evidence, empty closure roots, or missing
safe worker/target assignments are not splits. They are fail-closed validation
errors with exit code `42`.

## Artifacts

Each run emits:

- `batch_manifest.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

## Proof

The smoke harness is:

```bash
./scripts/e2e/locality_aware_remote_proof_batch_packer_smoke.sh check
./scripts/e2e/locality_aware_remote_proof_batch_packer_smoke.sh selftest
```

Required fixtures:

- two-suite shared-locality packing
- fairness-mandated split
- incompatible worker/target split
- deterministic repeated ordering with stable batch ids
