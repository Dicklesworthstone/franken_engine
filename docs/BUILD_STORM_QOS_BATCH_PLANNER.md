# Build Storm QoS Batch Planner

`scripts/build_storm_qos_batch_planner.sh` turns a pile of pending validation
requests into a deterministic execution batch. It is a planning gate only: it
does not run commands, mutate the worktree, or acquire leases.

The planner exists for swarm moments where many agents want heavy proof runs at
the same time. It keeps P0/P1 fail-closed proof refreshes moving while stopping
one agent or bead family from monopolizing `rch` capacity.

## Inputs

- `--pending-requests-json`: validation requests with `request_id`, `agent_id`,
  `bead_id`, `bead_priority`, `command`, and optional `proof_refresh`,
  `fail_closed_proof_refresh`, `stale_proof_refresh`, `docs_only`, and
  `broad_check` fields.
- `--resource-lease-plans-json`: receipts from
  `scripts/swarm_resource_lease_planner.sh`. Non-admitted leases are deferred
  with the lease reason preserved in the batch plan.
- `--proof-cost-history-json`: historical cost rows used to fill missing
  request estimates.
- `--rch-workers-json`: worker health rows. Only `idle`, `available`, and `ok`
  workers count toward `max_parallel_heavy`.

## Output Fields

- `batch_id`: stable hash-derived batch identifier for the input set.
- `admitted_commands`: commands selected for the next execution batch.
- `deferred_commands`: commands held back by lease status, worker capacity, or
  fairness rules.
- `fairness_reason`: top-level explanation of the batch decision.
- `max_parallel_heavy`: effective heavy-command capacity after worker health is
  applied.
- `retry_after_seconds`: shortest retry window among deferred commands.
- `stable_output_hash`: deterministic hash of the decision payload, excluding
  artifact paths.

Each admitted or deferred command carries its own `fairness_reason`, so
operator logs explain why work moved or waited.

## Operator Flow

Capture the queue and worker state, then plan the next batch:

```bash
./scripts/build_storm_qos_batch_planner.sh \
  --pending-requests-json /tmp/pending-validation-requests.json \
  --resource-lease-plans-json /tmp/resource-lease-plans.json \
  --proof-cost-history-json /tmp/proof-cost-history.json \
  --rch-workers-json /tmp/rch-workers.json \
  --max-parallel-heavy 4 \
  --max-per-agent-heavy 1
```

If a heavy proof is admitted, run it separately with the preserved command
shape. Heavy Rust commands should already use:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_<bead> \
  cargo test -p frankenengine-engine --test focused_proof_suite -- --nocapture
```

The planner never executes that command; it only records whether the command is
admitted for the batch.

## Fairness Policy

Requests are ordered deterministically by proof urgency, stale-proof status,
bead priority, broad-check penalty, wait time, agent id, bead id, and request id.

The planner then applies:

- global heavy capacity from `--max-parallel-heavy` and idle worker count
- per-agent heavy capacity from `--max-per-agent-heavy`
- resource lease decisions from the upstream lease planner
- a short retry window for stale proof refreshes deferred only by batch pressure

Docs-only and shell-only checks are admitted outside the heavy-command budget
when their lease receipt allows them.

## Smoke Validation

```bash
bash -n scripts/build_storm_qos_batch_planner.sh
bash -n scripts/e2e/build_storm_qos_batch_planner_smoke.sh
./scripts/e2e/build_storm_qos_batch_planner_smoke.sh check
./scripts/e2e/build_storm_qos_batch_planner_smoke.sh selftest
```

The smoke suite covers balanced two-agent admission, noisy-agent throttling,
P1 proof refresh preemption over a P3 broad check, all-workers-busy deferral,
stale proof refresh short retry windows, and stable output hashes across
repeated runs.
