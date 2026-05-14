# Optimization Promotion Replay Drill

The optimization promotion replay drill is advisory only and proof only.

It invokes the real promotion-control child producers over checked-in deterministic fixtures and a checked-in real hot-path evidence bundle shape.

The drill emits `run_manifest.json`, `events.jsonl`, `commands.txt`, `trace_ids.json`, per-stage JSON outputs, and `report.md`.

Replay mode verifies stable hashes and every stage output schema from a pinned run manifest.

The drill covers promotable evidence, stale evidence, transfer refusal, rollback demotion, synthetic contamination, and missing artifact fail_closed cases.

Every emitted validation command is rch-wrapped, and the drill itself never runs Cargo or RCH.

Truth-gate boundaries forbid live mutation claims, automatic benchmark publication, bare Cargo validation, and denominator-win claims without release gates.

## Artifacts

`scripts/optimization_promotion_replay_drill.sh` emits:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `trace_ids.json`
- `report.md`
- per-stage JSON outputs under `stages/`

The smoke harness is `scripts/e2e/optimization_promotion_replay_drill_smoke.sh`.
