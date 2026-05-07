# SWARM_AUTOPILOT_HINDSIGHT_CHAOS

`scripts/swarm_autopilot_hindsight_chaos.sh` generates replayable what-if and
chaos scenarios from completed swarm autopilot evidence bundles.

Machine-readable contract:
`docs/swarm_autopilot_hindsight_chaos_contract_v1.json`.

Checked-in fixture bundle:
`scripts/testdata/swarm_autopilot_hindsight_chaos/cases.json`.

Smoke harness:
`scripts/e2e/swarm_autopilot_hindsight_chaos_smoke.sh`.

The hindsight chaos generator is advisory only and proof only.

## Inputs

Required:

- `--source-bundle-json FILE`

Optional:

- `--source-revision REV`
- `--output-dir DIR`

The source bundle points at completed brownout forecast, operator policy, queue
advisory, resource lease plan, scarcity receipt, and recommendation-bundle
evidence paths. The generator records those paths; it does not invoke or mutate
the producers.

## Outputs

Each run emits:

- `swarm_autopilot_hindsight_chaos_scenarios.json`
- `swarm_autopilot_hindsight_chaos_replay_index.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

Each scenario preserves:

- source bundle id and original evidence paths
- perturbation type and minimal delta
- deterministic scenario hash
- stress targets for forecast, policy compiler, lease allocator, and recommendation bundle
- exact replay command
- expected invariant
- replay readiness

## Scenario Rules

Minimal perturbations must preserve the original evidence link and record only the delta.

Brownout chaos must stress RCH slot availability, target-dir pressure, and proof-cache pressure without changing live workers.

Stale ownership chaos must stress stale progress, stale br/bv state, and human-review recommendation behavior.

Local fallback chaos is quarantine-only and cannot produce replayable remote-only scenarios.

## Fail-Closed Rules

- Under-specified replay commands or expected invariants fail closed.
- Local fallback contamination fails closed.
- Stale source bundles fail closed.
- Missing source artifact paths fail closed.
- Schema drift in the source bundle fails closed.

The generator never mutates beads, releases reservations, sends Agent Mail,
runs Cargo, runs RCH, mutates workers, changes live queue policy, approves
replay automatically, or promotes recommendations automatically. It only emits
hindsight chaos scenarios and replay indexes under its output directory.

## Proof Cases

The checked-in fixtures cover:

- `minimal_perturbation_generation`
- `brownout_chaos`
- `stale_ownership_chaos`
- `local_fallback_chaos`
- `under_specified_replay_rejection`

## Validation

```bash
bash -n scripts/swarm_autopilot_hindsight_chaos.sh
bash -n scripts/e2e/swarm_autopilot_hindsight_chaos_smoke.sh
shellcheck -x scripts/swarm_autopilot_hindsight_chaos.sh scripts/e2e/swarm_autopilot_hindsight_chaos_smoke.sh
jq empty docs/swarm_autopilot_hindsight_chaos_contract_v1.json scripts/testdata/swarm_autopilot_hindsight_chaos/cases.json
bash scripts/e2e/swarm_autopilot_hindsight_chaos_smoke.sh check
bash scripts/e2e/swarm_autopilot_hindsight_chaos_smoke.sh selftest
git diff --check -- docs/SWARM_AUTOPILOT_HINDSIGHT_CHAOS.md docs/swarm_autopilot_hindsight_chaos_contract_v1.json scripts/swarm_autopilot_hindsight_chaos.sh scripts/e2e/swarm_autopilot_hindsight_chaos_smoke.sh scripts/testdata/swarm_autopilot_hindsight_chaos/cases.json
```
