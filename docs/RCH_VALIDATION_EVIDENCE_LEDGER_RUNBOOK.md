# RCH Validation Evidence Ledger Runbook

`bd-7r53m.4`

The RCH validation evidence ledger records source-only checks, focused RCH
proofs, broad-gate attempts, and blocked validation reasons in one JSON object.
Each entry must include `bead_id`, `commit`, `command`, `command_class`, and
`result.status`.

Artifacts:

- schema: `docs/rch_validation_evidence_ledger_schema_v1.json`
- sample: `docs/rch_validation_evidence_ledger_sample_v1.json`
- verifier: `scripts/verify_rch_validation_evidence_ledger.sh`

## RCH-E104 With No Diagnostic

When an RCH receipt reports `RCH-E104` or a timeout and
`compiler_diagnostic_surfaced` is `false`, treat it as infrastructure evidence,
not a code failure. Preserve the highest reached `compile_stage_reached` value:
`syncing_project`, `resolving_dependencies`, `compiling_dependencies`,
`compiling_target_crate`, `test_harness`, `completed`, or `unknown`.

Next action:

- focused proof: retry with the bead-correlated warm target dir from the command
  matrix after checking admission.
- broad gate: wait for the existing all-targets job or publish a blocked reason.
- source-only work: keep the source check proof and do not inflate it into
  compile proof.

## Worker Disk Full

When the result is `worker_disk_full`, keep the failed worker id in telemetry,
classify the result as infrastructure, and route the next attempt to a different
worker or source-only proof. Do not retry locally after a remote disk failure.

## Active All-Targets Contention

Before launching another heavy proof, run
`scripts/swarm_validation_admission_recommender.sh` with captured process, bead,
and dirty-file snapshots. If it returns `wait_existing_all_targets`, attach that
recommendation as a `blocked_reason` ledger entry and keep moving on source-only
checks or a narrower focused proof.

## Verification

```bash
jq empty docs/rch_validation_evidence_ledger_schema_v1.json docs/rch_validation_evidence_ledger_sample_v1.json
bash -n scripts/verify_rch_validation_evidence_ledger.sh
./scripts/verify_rch_validation_evidence_ledger.sh docs/rch_validation_evidence_ledger_sample_v1.json
git diff --check -- docs/RCH_VALIDATION_EVIDENCE_LEDGER_RUNBOOK.md docs/rch_validation_evidence_ledger_schema_v1.json docs/rch_validation_evidence_ledger_sample_v1.json scripts/verify_rch_validation_evidence_ledger.sh scripts/e2e/rch_validation_evidence_ledger_smoke.sh
```
