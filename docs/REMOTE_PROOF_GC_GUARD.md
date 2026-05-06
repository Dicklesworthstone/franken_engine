# Remote Proof GC Guard

`scripts/remote_proof_gc_guard.sh` is the fail-closed deletion classifier for
SWARM-CTRL-VI. It evaluates one remote-proof artifact set and answers whether
the set must stay hot, stay pinned, cool without deletion, or may be deleted.

## Inputs

Required:

- `--retention-ledger-json`
- `--warm-target-roi-ledger-json`
- `--salvage-receipt-json`
- `--archive-pack-json`

Optional:

- `--output-dir`

The archive-pack input is intentionally future-compatible with the archive
exporter lane. The guard only reads state and verification evidence; it does not
delete files or contact remote workers.

## Output

Each run emits:

- `remote_proof_gc_guard_report.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The report records:

- `guard_decision`
- `recommended_action`
- `policy_findings`
- `gc_eligible`
- summaries for retention, ROI, salvage, and archive state

## Decision Rules

- `deny_gc` with `keep_hot` when warm-target ROI still requires active hot
  residency.
- `deny_gc` with `pin_until_salvage_clears` when salvage reconciliation is still
  active, especially orphan-reconciliation cases.
- `allow_gc` with `delete_cold_archived_bundle` only when the retention ledger
  shows a cold-only set and the archive pack reports cold archival plus restore
  verification.
- `cool_only` with `cool_without_gc` when the set is not pinned but is not yet
  cold-and-verified enough for deletion.
- `fail_closed` when upstream evidence drifts or is incomplete.

## Proof Expectations

`scripts/e2e/remote_proof_gc_guard_smoke.sh` must prove:

- active warm-target bundle protected from GC
- orphan-salvage bundle pinned
- cold archived bundle allowed for GC
- repeated identical inputs preserve the same guard hash
