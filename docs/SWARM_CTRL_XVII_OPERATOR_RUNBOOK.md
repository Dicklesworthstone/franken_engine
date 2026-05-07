# SWARM-CTRL-XVII Operator Runbook

This runbook defines the no-mock catalog drill for the SWARM-CTRL-XVII control-surface catalog. It is a repository-local evidence drill for routing, drift, intake, and operator-status handoff behavior.

The drill uses the real catalog normalizer, intent router, drift gate, intake guard, and operator status reporter.
scripts/swarm_operator_status_report.sh remains the only operator-status producer.

## Scope

The drill reads checked-in contracts plus temporary JSON fixtures written under a caller-selected artifact directory. It proves the existing catalog control surfaces can route operator intent and reject unsafe follow-on work without touching live coordination state.

The drill covers these cases:

- healthy catalog routes an RCH stall intent to `swarm_rch_stall_rehabilitation_ledger`
- actionability divergence routes to `swarm_actionability_truth_gate`
- a duplicate proposed feature is rejected by the intake guard
- an uncataloged script fails the drift gate
- operator status exposes the catalog handoff
- shadow-daemon adoption remains blocked or degraded when its upstream bead is active

## Boundary

The catalog drill is advisory-only and fixture-fed. It does not mutate br.
The catalog drill does not query live Agent Mail.
The catalog drill does not send Agent Mail.
The catalog drill does not release reservations.
The catalog drill does not run Cargo.
The catalog drill does not run RCH.
The catalog drill does not change queue policy.
The catalog drill does not replace operator status.

The emitted reports can be attached to a bead or human review, but any queue, mail, reservation, build, or remote-worker action must be performed by the operator as a separate explicit step.

## Commands

Run the no-mock drill:

```bash
bash scripts/e2e/swarm_control_surface_catalog_no_mock_drill.sh check
```

Run the drill selftest:

```bash
bash scripts/e2e/swarm_control_surface_catalog_no_mock_drill.sh selftest
```

Run the runbook truth gate:

```bash
bash scripts/e2e/swarm_control_surface_catalog_runbook_truth_gate.sh check
```

Run the truth-gate selftest:

```bash
bash scripts/e2e/swarm_control_surface_catalog_runbook_truth_gate.sh selftest
```

## Artifacts

The no-mock drill writes:

- `swarm_control_surface_catalog_no_mock_drill_report.json`
- `events.jsonl`
- `commands.txt`
- `report.md`
- component artifacts from the normalizer, router, drift gate, intake guard, and operator-status reporter

The truth gate writes:

- `runbook_truth_report.json`
- `commands.txt`
- `report.md`

Both scripts default to temporary artifact roots under `${TMPDIR:-/tmp}` and accept environment variables for deterministic artifact directories.
