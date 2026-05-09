# Swarm Proof Broker Chaos Replay

`bd-ua5n2.7`

`scripts/swarm_proof_broker_chaos_replay.sh` generates deterministic,
replayable chaos scenarios for the proof broker. It preserves original proof
request evidence, applies minimal deltas, emits a deterministic scenario hash,
and writes exact replay commands for the classifier, artifact index, batch
planner, and operator-status projection.

The generator never runs Cargo or RCH and never mutates br, Agent Mail, remote
workers, live queues, or target directories. Replay commands are emitted into
`replay_commands.sh` for operators to run separately.

## Scenario Coverage

- `duplicate_proof_storm`: duplicate command bursts must coalesce without
  hiding the duplicated request ids.
- `stale_artifact_storm`: expired artifacts must drive artifact-index refusal,
  batch deferral, and stale operator-status rows.
- `dirty_worktree_divergence`: changed dirty paths or dependency roots must
  refuse reuse instead of treating prior proof as green.
- `rch_local_fallback_contamination`: local fallback contamination must refuse
  reuse and surface a contaminated operator status.
- `agent_mail_degraded_capture`: degraded Agent Mail state stays visible in the
  replay evidence and invariant projection.
- `missing_source_evidence`: scenarios that lack enough source evidence fail
  closed before claiming replayability.

Each scenario includes component fixture inputs so the four downstream advisory
surfaces can be replayed independently.
Scenarios with insufficient source evidence fail closed.

## Validation

```bash
jq empty docs/swarm_proof_broker_chaos_replay_contract_v1.json scripts/testdata/swarm_proof_broker_chaos_replay/cases.json
bash -n scripts/swarm_proof_broker_chaos_replay.sh
bash -n scripts/e2e/swarm_proof_broker_chaos_replay_smoke.sh
bash scripts/e2e/swarm_proof_broker_chaos_replay_smoke.sh check
bash scripts/e2e/swarm_proof_broker_chaos_replay_smoke.sh selftest
git diff --check -- scripts/swarm_proof_broker_chaos_replay.sh docs/SWARM_PROOF_BROKER_CHAOS_REPLAY.md docs/swarm_proof_broker_chaos_replay_contract_v1.json scripts/testdata/swarm_proof_broker_chaos_replay/cases.json scripts/e2e/swarm_proof_broker_chaos_replay_smoke.sh
```
