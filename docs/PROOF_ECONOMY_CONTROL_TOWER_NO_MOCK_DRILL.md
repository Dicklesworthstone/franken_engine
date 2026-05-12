# Proof Economy Control Tower No-Mock Drill

`scripts/e2e/proof_economy_control_tower_no_mock_drill.sh` is the operator drill for the proof-economy control tower. It is fixture-fed and read-only, but it runs the real component scripts:

- `scripts/proof_reuse_admission_bundle.sh`
- `scripts/proof_queue_tail_latency_rescue_gate.sh`
- `scripts/agent_run_evidence_index.sh`
- `scripts/proof_economy_control_tower.sh`

The fixture bundle preserves br, git, Agent Mail health, rch log, and proof artifact snapshots. The drill writes `run_manifest.json`, `events.jsonl`, `commands.txt`, `trace_ids.json`, `operator_report.json`, `report.md`, and per-case subordinate component reports.

## Commands

```bash
./scripts/e2e/proof_economy_control_tower_no_mock_drill.sh check
./scripts/e2e/proof_economy_control_tower_no_mock_drill.sh run
./scripts/e2e/proof_economy_control_tower_no_mock_drill.sh replay --replay-run-dir artifacts-or-temp-run-dir
./scripts/e2e/proof_economy_control_tower_no_mock_drill.sh selftest
```

The drill never queries live Agent Mail, mutates br, releases reservations, sends Agent Mail, runs Cargo, runs rch, mutates remote workers, or alters live queue policy.

## Fail-Closed Coverage

The operator report must prove these cases:

- degraded Agent Mail plus rch timeout with remediation
- missing RCH manifest
- local Cargo fallback contamination in rch evidence
- duplicate proof reuse without source-hash match
- advisory-mode mutation attempt

Replay mode verifies the saved artifacts and subordinate JSON reports without rerunning the component scripts.
