# SWARM-CTRL-IV Residency Remote Proof Acceleration Runbook

This runbook is the operator surface for the SWARM-CTRL-IV residency track. It
keeps repeated proof suites warm, bounded, and truthful by composing the four
downstream artifact surfaces:

- `sticky_worker_warm_target_plan.json`
- `sync_closure_hotspots.json`
- `artifact_retrieval_budget_verdict.json`
- `incident_packet.json`

The combined no-mock drill publishes `residency_drill_report.json`.

## Scope

The residency track is shell/docs/artifact-only. It does not patch the `rch`
daemon and it does not run local heavy Cargo.

Heavy proof examples stay in this form:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_residency cargo test -p frankenengine-engine --test semantic_dark_matter_engine_integration -- --nocapture
```

## Operator Flow

1. Generate a sticky worker and warm target-dir plan:

```bash
bash scripts/e2e/sticky_worker_warm_target_lease_planner_smoke.sh selftest
```

2. Classify repeated sync-closure hotspots from preserved suite logs:

```bash
bash scripts/e2e/rch_sync_closure_hotspot_ledger_smoke.sh selftest
```

3. Fail closed if replay retrieval exceeds the minimal artifact budget:

```bash
bash scripts/e2e/artifact_retrieval_budget_manifest_gate_smoke.sh selftest
```

4. Classify remote proof failures, including orphaned remote compile evidence:

```bash
bash scripts/e2e/rch_incident_packet_gate_smoke.sh selftest
```

5. Compose the residency drill:

```bash
bash scripts/e2e/swarm_residency_remote_proof_drill.sh selftest
cat /tmp/franken-engine-swarm-residency-remote-proof-drill*/warm-worker-success/residency_drill_report.json
```

The drill must prove:

- warm-worker success across `check`, `test`, and `clippy`
- repeated full-sync hotspot evidence
- retrieval over-budget rejection
- orphaned compile incident rejection

## Truth Gate

Run the residency runbook truth gate whenever this runbook or the drill changes:

```bash
bash scripts/e2e/swarm_residency_remote_proof_runbook_truth_gate.sh check
bash scripts/e2e/swarm_residency_remote_proof_runbook_truth_gate.sh selftest
```

The truth gate rejects:

- bare heavy Cargo examples that are not `rch exec -- env CARGO_TARGET_DIR=` wrapped
- missing references to the four required child artifacts
- missing references to `residency_drill_report.json`
