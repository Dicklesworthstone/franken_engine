# Topology-Aware Queue No-Mock Drill

`scripts/e2e/swarm_topology_aware_queue_no_mock_drill.sh` composes the
checked-in SWARM-SCALE-III topology queue fixtures through the real topology
queue signal normalizer, topology-aware queue scorer, topology-aware queue
fidelity ledger, and operator-status reporter.

The drill is fixture-fed, proof-only, and advisory-only. It does not run Cargo
or RCH work, mutate live workers, pin workers automatically, change live queue
policy, reroute tasks automatically, edit `br`, release reservations, or send
Agent Mail.

## Coverage

The drill proves:

- healthy balanced host advice prefers hot-cache locality and records actual
  locality/cache reuse success in the fidelity ledger
- missing locality or adoption evidence remains degraded instead of healthy by
  default
- contradictory locality blocks queue-ranking advice
- drain-recommended and probe-required workers are excluded from preferred
  advice
- repeated unstable-worker evidence downgrades or blocks locality-aware queue
  advice instead of silently trusting it
- local fallback contamination fails closed before topology-aware queue advice
  is trusted

## Verification

```bash
bash -n scripts/e2e/swarm_topology_aware_queue_no_mock_drill.sh scripts/e2e/swarm_topology_aware_queue_truth_gate.sh
shellcheck -x scripts/e2e/swarm_topology_aware_queue_no_mock_drill.sh scripts/e2e/swarm_topology_aware_queue_truth_gate.sh
jq empty docs/swarm_topology_aware_queue_no_mock_drill_contract_v1.json scripts/testdata/swarm_topology_aware_queue_no_mock_drill/cases.json
bash scripts/e2e/swarm_topology_aware_queue_truth_gate.sh check
bash scripts/e2e/swarm_topology_aware_queue_truth_gate.sh selftest
bash scripts/e2e/swarm_topology_aware_queue_no_mock_drill.sh check
bash scripts/e2e/swarm_topology_aware_queue_no_mock_drill.sh selftest
```

The selftest emits `swarm_topology_aware_queue_no_mock_drill_report.json`,
`events.jsonl`, `commands.txt`, `report.md`, and one case directory per
scenario under the selected output directory.
