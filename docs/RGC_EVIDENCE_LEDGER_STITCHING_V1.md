# RGC Evidence Ledger Stitching v1

Bead: `bd-1lsy.9.11.2`

This contract operationalizes the evidence-ledger stitching surface for
FrankenEngine decisions. It publishes one deterministic bundle that links:

- hindsight boundary captures
- decision semantics
- artifact lineage
- operator/query-facing evidence lookup

The goal is to make the existing stitching logic consumable by verification,
support, rollout, and release tooling without bespoke forensic reconstruction.

## Required Artifacts

- `artifact_lineage_index.json`
- `commands.txt`
- `decision_semantics_log.jsonl`
- `env.json`
- `evidence_ledger_graph.json`
- `evidence_ledger_stitching_bundle.json`
- `evidence_query_surface_snapshot.json`
- `events.jsonl`
- `manifest.json`
- `repro.lock`
- `run_manifest.json`
- `summary.md`
- `trace_ids.json`

## Query Surface Fields

- `trace_id`
- `decision_id`
- `policy_id`
- `evidence_entry_id`
- `chosen_action`
- `boundary_correlation_keys`
- `artifact_ids`
- `witness_ids`
- `confidence_tier`
- `fallback_reason`

## Artifact Kinds

- `benchmark_manifest`
- `release_gate_report`
- `support_bundle`

## Graph Edge Kinds

- `boundary_informs_decision`
- `boundary_supports_artifact`
- `decision_produces_artifact`

## Verification

```bash
./scripts/run_rgc_evidence_ledger_stitching.sh ci
./scripts/e2e/rgc_evidence_ledger_stitching_replay.sh ci
```

The suite is `rch`-backed and emits the required bundle under
`artifacts/rgc_evidence_ledger_stitching/<timestamp>/`.
