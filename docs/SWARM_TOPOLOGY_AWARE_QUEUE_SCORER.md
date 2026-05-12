# SWARM_TOPOLOGY_AWARE_QUEUE_SCORER

`scripts/swarm_topology_aware_queue_scorer.sh` is the SWARM-SCALE-III-C
fixture-fed advisory scorer or planner for topology-aware execution-queue
ranking and cache reuse.

It composes the shipped topology queue signal input, the proof-cache locality
optimizer, queue artifact truth, bottleneck truth, and locality outcome
feedback into one replayable advisory bundle. It is advisory-only. It does not
run Cargo or RCH, mutate live workers, change live queue policy, pin workers,
edit beads, release reservations, or send Agent Mail.

## Inputs

Required inputs:

- `topology_queue_signal_input_json`
- `proof_cache_locality_plan_json`
- `queue_artifact_json`
- `bottleneck_report_json`
- `locality_outcome_samples_json`

Optional supporting inputs:

- `placement_adoption_history_json`
- `operator_status_snapshot_json`
- `resource_envelope_json`
- `tail_latency_locality_json`

## Artifacts

The scorer emits:

- `queue_advisory_bundle.json`
- `queue_advisory_sources.json`
- `events.jsonl`
- `commands.txt`
- `summary.md`

The advisory bundle preserves:

- `queue_advisory_id`
- `truth_state`
- `decision`
- `admission_decision`: `admit`, `narrow`, `defer`, or `fail_closed`
- `reason_codes`
- `worker_exclusions`
- `locality_bias_summary`
- `risk_budget_summary`
- `selected_command_policy`
- `feedback_summary`
- `source_artifacts`
- `artifact_paths`
- `mutation_policy`

## Truth Rules

- Local fallback contamination fails closed.
- Validation commands supplied by the queue signal must preserve `rch exec --`
  and an explicit `CARGO_TARGET_DIR=...`; unsafe broadening fails closed.
- Contradictory locality evidence blocks queue advice.
- Resource-envelope memory headroom below the topology admission floor defers
  proof admission.
- Missing target-dir evidence narrows admission advice until the proof-cache
  locality planner selects a target directory.
- Missing optional support evidence degrades confidence instead of healthy by
  default.
- Drained or probe-required worker exclusions degrade advice instead of keeping
  the original preferred set untouched.
- When feedback shows misses, cache reuse misses degrade the advisory instead
  of being counted as healthy reuse.
- The scorer must not claim it changed the live queue or pinned workers.

## Proof Cases

The checked-in fixtures cover:

- `healthy_confirmed`
- `degraded_missing_locality_support`
- `blocked_contradictory_locality`
- `contaminated_local_fallback`
- `drained_worker_exclusion`
- `cache_reuse_feedback`

## Validation

```bash
bash -n scripts/swarm_topology_aware_queue_scorer.sh
bash -n scripts/e2e/swarm_topology_aware_queue_scorer_smoke.sh
shellcheck -x scripts/swarm_topology_aware_queue_scorer.sh scripts/e2e/swarm_topology_aware_queue_scorer_smoke.sh
jq empty docs/swarm_topology_aware_queue_scorer_contract_v1.json scripts/testdata/swarm_topology_aware_queue_scorer/cases.json
bash scripts/e2e/swarm_topology_aware_queue_scorer_smoke.sh check
bash scripts/e2e/swarm_topology_aware_queue_scorer_smoke.sh selftest
git diff --check -- docs/SWARM_TOPOLOGY_AWARE_QUEUE_SCORER.md docs/swarm_topology_aware_queue_scorer_contract_v1.json scripts/swarm_topology_aware_queue_scorer.sh scripts/e2e/swarm_topology_aware_queue_scorer_smoke.sh scripts/testdata/swarm_topology_aware_queue_scorer/cases.json
```
