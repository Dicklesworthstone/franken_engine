# Swarm Ops No-Mock Drill

`scripts/e2e/swarm_ops_no_mock_drill.sh` composes the closed-loop SWARM-OPS operator path into one auditable bundle. It runs the shipped capture, admission, stale-recovery, RCH rehabilitation, proof-cache locality, dashboard, saturation replay, and SLO gate surfaces, then emits a truth-gate report over the combined evidence.

Machine-readable contract: `docs/swarm_ops_no_mock_drill_contract_v1.json`

Smoke gate: `scripts/e2e/swarm_ops_no_mock_drill_smoke.sh`

Fixture cases: `scripts/testdata/swarm_ops_no_mock_drill/cases.json`

## Modes

- Live no-mock mode captures the local repository state through `br`, `bv`, Agent Mail, RCH status, and git status via the existing state snapshot script.
- Fixture mode feeds preserved raw inputs through the same stage scripts for deterministic CI checks.
- Replay mode verifies an explicitly pinned run directory with `--replay-run-dir` or the latest child of a directory with `--latest-from`.

The drill does not mutate beads, release reservations, send Agent Mail, run heavy RCH work, execute Cargo, drain workers, or change queue policy. It only writes under its output directory.

## Bundle

Every complete run includes:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `trace_ids.json`
- `state_snapshot.json`
- `admission_plan.json`
- `recovery_receipts.json`
- `rch_rehab_ledger.json`
- `locality_plan.json`
- `dashboard_bundle.json`
- `saturation_replay_report.json`
- `slo_gate_report.json`
- `truth_gate_report.json`

The raw capture inputs remain under `stages/state_capture/out/raw/`, and per-stage stdout, stderr, commands, and native artifacts remain under `stages/`.

## Truth Gate

The truth gate fails closed when:

- stale `br`/`bv` export state does not propagate into admission fail-closed evidence
- RCH stale-progress or rehabilitation evidence is upgraded to `pass`
- a heavy Cargo command appears without an `rch exec` wrapper in command evidence
- local fallback contamination does not fail closed through the SLO gate
- a pinned replay bundle is missing required artifacts

Run fixture validation:

```bash
bash scripts/e2e/swarm_ops_no_mock_drill_smoke.sh check
bash scripts/e2e/swarm_ops_no_mock_drill_smoke.sh selftest
```

Run a live no-mock capture:

```bash
bash scripts/e2e/swarm_ops_no_mock_drill.sh --output-dir /tmp/swarm-ops-live
```

Replay a pinned bundle:

```bash
bash scripts/e2e/swarm_ops_no_mock_drill.sh --replay-run-dir /tmp/swarm-ops-live --output-dir /tmp/swarm-ops-live-replay
```
