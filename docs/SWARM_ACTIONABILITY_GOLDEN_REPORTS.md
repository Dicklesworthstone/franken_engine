# SWARM_ACTIONABILITY_GOLDEN_REPORTS

`bd-p02f6` freezes reviewed golden reports for the V1 actionability truth
contract.

These reports are characterization artifacts, not live implementation output.
They give `scripts/swarm_actionability_truth_gate.sh` and later no-mock drills a
stable comparison target once those paths are ready.

## Golden Coverage

The golden file covers the six contract fixture cases:

- `healthy_ready_safe_to_claim`
- `bv_blocked_track_fail_closed`
- `in_progress_owned_defer`
- `stale_export_fail_closed`
- `dirty_overlap_defer`
- `missing_optional_mail_observe_only`

Every report includes the required V1 output shape:

- schema version
- scrubbed source revision
- decision
- candidate summary
- candidate reports with source ids and evidence paths
- fail-closed reasons
- advisory remediation commands
- source freshness summary
- mutation policy

## Review Loop

Intentional golden changes must be reviewed as behavior changes:

1. Update `scripts/testdata/swarm_actionability_golden_reports/reports.json`.
2. Run `scripts/e2e/swarm_actionability_golden_reports_smoke.sh selftest`.
3. Review the JSON diff before committing.

The smoke gate rejects live timestamps, host paths, Cargo/RCH commands, and any
mutation-capable policy claim. Dynamic source metadata is represented with
`[SCRUBBED_*]` markers so the golden remains stable across hosts and runs.
