# Swarm Admission Drill

`scripts/e2e/swarm_admission_drill.sh` is the no-mock drill for the
SWARM-CTRL-III admission flow. It runs the real shell gates over checked-in
fixtures that model a 20-agent swarm, mixed P1/P2 beads, rch worker pressure,
dirty worktree paths, proof artifacts, and staged-file contamination.

The drill does not execute heavy proof commands. Heavy commands appear only as
planner inputs and must already use `rch exec -- env CARGO_TARGET_DIR=...`.

## Child Gates

The drill invokes:

- `scripts/swarm_resource_lease_planner.sh`
- `scripts/proof_reuse_cache_planner.sh`
- `scripts/build_storm_qos_batch_planner.sh`
- `scripts/swarm_admission_budget_planner.sh`
- `scripts/stale_lock_stalled_bead_recommender.sh`
- `scripts/staged_ownership_contamination_guard.sh`

It then emits `swarm_admission_drill_report.json`, `events.jsonl`,
`commands.txt`, and `report.md`.

## Required Observations

The combined report fails unless it sees:

- one admitted heavy proof
- one proof cache hit
- one stale proof refresh
- one deferred noisy agent
- one stale-lock contact-first recommendation
- one staged contamination rejection
- one protected-priority budget recommendation that survives pressure
- one speculative request deferred by the budget planner

Replay mode validates an existing artifact bundle without rerunning child gates:

```bash
./scripts/e2e/swarm_admission_drill.sh replay \
  --artifact-dir /tmp/franken-engine-swarm-admission-drill/20260506T000000Z
```

## Predictive Composition

SWARM-CTRL-VIII reuses this drill through
`scripts/e2e/swarm_predictive_admission_no_mock_drill.sh`. That wrapper
consumes `swarm_admission_drill_report.json` directly alongside the predictive
orchestration and archive-pressure drill reports. It extends this admission
surface as proof-only composition; it does not replace this drill or become a
second predictive dashboard producer.

## Validation

```bash
bash -n scripts/e2e/swarm_admission_drill.sh
./scripts/e2e/swarm_admission_drill.sh check
./scripts/e2e/swarm_admission_drill.sh selftest
./scripts/e2e/swarm_predictive_admission_no_mock_drill.sh check
./scripts/e2e/swarm_predictive_admission_no_mock_drill.sh selftest
```

The fixture suite intentionally includes rch-wrapped heavy examples such as:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_admission_alpha \
  cargo test -p frankenengine-engine --test semantic_dark_matter_pipeline -- --nocapture
```
