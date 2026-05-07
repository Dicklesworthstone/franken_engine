# Swarm Autopilot Evidence Warehouse

`scripts/swarm_autopilot_evidence_warehouse.sh` normalizes SWARM-OPS no-mock
bundles, topology-aware queue advice, RCH rehabilitation ledgers, SLO gate
reports, and optional operator-intent policy snapshots into a single
append-only warehouse record for the forecast-driven swarm autopilot.

Machine-readable contract: `docs/swarm_autopilot_evidence_warehouse_contract_v1.json`

Smoke gate: `scripts/e2e/swarm_autopilot_evidence_warehouse_smoke.sh`

Fixture cases: `scripts/testdata/swarm_autopilot_evidence_warehouse/cases.json`

## Inputs

Required inputs:

- `swarm_ops_bundle_dir`
- `queue_locality_json`

Optional supporting inputs:

- `operator_intent_policy_json`

The warehouse preserves raw artifact paths and emits normalized source
fingerprints, source revisions, run identity, freshness markers, local-fallback
contamination state, and retention classes.

## Artifacts

Every run emits:

- `evidence_warehouse.json`
- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The warehouse record contains:

- `artifact_rows`
- `fail_closed_reasons`
- `remediation_commands`
- `retention_classes`
- `hash_basis`
- `artifact_paths`
- `mutation_policy`

The stable `warehouse_hash` is calculated from normalized content hashes,
source ids, schemas, decisions, freshness markers, retention classes, source
revision, and fail-closed reasons. It excludes output paths, raw source paths,
normalized temp paths, wall-clock run ids, and generated artifact paths.

## Truth Rules

- Missing SWARM-OPS bundle members fail closed.
- Schema drift in required evidence fails closed.
- Stale `br`/`bv` sync evidence fails closed.
- Local fallback contamination fails closed.
- Contradictory truth-gate and stage decisions fail closed.
- Missing topology-aware queue locality evidence fails closed.
- Provided operator-intent policies must match the contract schema.

Every fail-closed reason carries a concrete remediation command in the warehouse
and in `report.md`.

The warehouse is proof-only and fixture-fed. It does not mutate beads, reassign
work, release reservations, send Agent Mail, run Cargo, run RCH, mutate workers,
pin workers, or change live queue policy. It only writes under its output
directory.

## Proof Cases

The checked-in fixtures cover:

- `green`
- `stale_swarm_ops`
- `missing_queue_locality`
- `local_fallback_contamination`
- `schema_drift`

## Validation

```bash
bash -n scripts/swarm_autopilot_evidence_warehouse.sh scripts/e2e/swarm_autopilot_evidence_warehouse_smoke.sh
shellcheck -x scripts/swarm_autopilot_evidence_warehouse.sh scripts/e2e/swarm_autopilot_evidence_warehouse_smoke.sh
jq empty docs/swarm_autopilot_evidence_warehouse_contract_v1.json scripts/testdata/swarm_autopilot_evidence_warehouse/cases.json
bash scripts/e2e/swarm_autopilot_evidence_warehouse_smoke.sh check
bash scripts/e2e/swarm_autopilot_evidence_warehouse_smoke.sh selftest
git diff --check -- docs/SWARM_AUTOPILOT_EVIDENCE_WAREHOUSE.md docs/swarm_autopilot_evidence_warehouse_contract_v1.json scripts/swarm_autopilot_evidence_warehouse.sh scripts/e2e/swarm_autopilot_evidence_warehouse_smoke.sh scripts/testdata/swarm_autopilot_evidence_warehouse/cases.json
```
