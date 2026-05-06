# SWARM_EXECUTION_QUEUE_CONFORMANCE

`scripts/e2e/swarm_execution_queue_conformance_gate.sh` freezes the
SWARM-CTRL-XII execution queue runner behavior against deterministic checked-in
fixtures and goldens.

The gate is advisory-only. It validates fixture, golden, contract, and optional
runner replay artifacts; it does not mutate `br`, change bead assignees, release
reservations, send messages, or touch remote worker state.

## Coverage

The fixture set covers:

- `healthy_input.json`: a ready task with deterministic queue rank, first action,
  low bottleneck classification, and stable artifact hash.
- `stale_owner_input.json`: degraded stale-owner evidence with contact/reopen
  first action and stale-owner bottleneck classification.
- `proof_brownout_input.json`: degraded proof transport with conservative risk
  budget mode and a narrower no-cargo first action.
- `blocked_parent_input.json`: dependency ordering where the child is queued
  before the blocked parent.
- `cyclic_input.json`: fail-closed dependency cycle evidence with expected exit
  code `42`.

The checked-in runner goldens live under
`scripts/testdata/swarm_execution_queue/goldens/`. They freeze queue order,
rank values, first actions, fallback triggers, risk-budget receipts, bounded
queue depth, bottleneck IDs, and stable artifact hashes.

## Modes

`check` validates the docs, contract, fixture shapes, golden shapes, and rch
policy for this lane.

`selftest` runs `check` and then proves malformed fixtures, mutated goldens,
contract gaps, and live-mutation wording are rejected.

If `FRANKEN_SWARM_EXECUTION_QUEUE_BIN` points at an executable
`franken_swarm_execution_queue`, either mode also replays the real runner
against the checked-in fixtures and compares its compact output to the frozen
goldens.

## Validation

```bash
bash -n scripts/e2e/swarm_execution_queue_conformance_gate.sh
shellcheck -x scripts/e2e/swarm_execution_queue_conformance_gate.sh
jq empty docs/swarm_execution_queue_conformance_contract_v1.json scripts/testdata/swarm_execution_queue/*.json scripts/testdata/swarm_execution_queue/goldens/*.json
bash scripts/e2e/swarm_execution_queue_conformance_gate.sh check
bash scripts/e2e/swarm_execution_queue_conformance_gate.sh selftest
```
