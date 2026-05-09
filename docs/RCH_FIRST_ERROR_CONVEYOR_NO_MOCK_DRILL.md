# RCH First Error Conveyor No-Mock Drill

`scripts/e2e/rch_first_error_conveyor_no_mock_drill.sh` exercises the shipped
compile-blocker cluster and first-error conveyor scripts against preserved
transcript-shaped fixtures. It is a replay drill for handoff evidence, not a
live compile runner.

Machine-readable contract:
`docs/rch_first_error_conveyor_no_mock_drill_contract_v1.json`.

Fixture bundle:
`scripts/testdata/rch_first_error_conveyor_no_mock_drill/cases.json`.

## Modes

- `fixture`: runs the real shipped cluster and conveyor scripts over preserved
  rch transcript snippets, br export-style ownership snapshots, and Agent
  Mail-style reservation or announcement snapshots.
- `replay`: verifies a previously emitted bundle and its artifact hashes without
  rerunning producers.
- `check`: validates shell syntax and fixture/contract shape.
- `selftest`: fixture mode followed by replay mode.

The drill does not run Cargo, invoke `rch`, create beads, update beads, send
Agent Mail, mutate files outside the output directory, or mutate workers.

## Required Coverage

- first error chain blocks the current bead
- blocked golden lane dedupes to an existing bead
- blocked Object.create lane dedupes to an existing bead
- fresh active owner defers work
- stale owner remains visible as a manual reopen candidate
- local fallback contamination fails closed

## Operator Commands

```bash
scripts/e2e/rch_first_error_conveyor_no_mock_drill_smoke.sh check
scripts/e2e/rch_first_error_conveyor_no_mock_drill_smoke.sh selftest
```

To keep a bundle for manual replay:

```bash
scripts/e2e/rch_first_error_conveyor_no_mock_drill.sh fixture --output-dir /tmp/first-error-drill
scripts/e2e/rch_first_error_conveyor_no_mock_drill.sh replay --replay-run-dir /tmp/first-error-drill --output-dir /tmp/first-error-replay
```

`truth_gate_report.json` records coverage and pass/fail state. `artifact_hashes.json`
pins every emitted artifact except the hash index itself.
