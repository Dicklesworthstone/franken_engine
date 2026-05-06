# SWARM_EXECUTION_QUEUE_RUNNER

`franken_swarm_execution_queue` replays a normalized SWARM-CTRL-XII execution
queue input through the Rust `SwarmControlLoop`.

The runner is advisory-only. It writes deterministic artifacts for operator
review, but it does not update beads, reassign owners, release reservations,
send Agent Mail, run cargo, or mutate remote workers.

## Input

The runner consumes `franken-engine.swarm-execution-queue-input.v1` JSON from
`scripts/swarm_execution_queue_input_normalizer.sh`.

Required CLI shape:

```bash
franken_swarm_execution_queue --normalized-input-json normalized_input.json --output-dir artifacts/swarm_execution_queue/run
```

Optional flags:

- `--queue-depth N`
- `--epoch N`
- `--timestamp-ns N`
- `--include-gated`

## Artifacts

Each successful run emits:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `execution_queue_artifact.json`
- `risk_budget_receipt.json`
- `bottleneck_report.json`
- `operator_summary.md`

The queue artifact preserves `SwarmControlLoop` ordering, wave assignment,
EV/relevance scoring, risk-budget conservative mode, rationale deltas, and
bottleneck severity.

## Fail-Closed Behavior

The runner rejects empty graphs, unknown dependencies, dependency cycles,
oversized graphs, invalid queue depths, local-rch fallback promotion, input
marked `fail_closed`, and degraded evidence kinds that the runner does not
recognize.

## Validation

```bash
rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_swarm_execution_queue cargo check -p frankenengine-engine --bin franken_swarm_execution_queue
rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_swarm_execution_queue cargo test -p frankenengine-engine --test swarm_execution_queue_runner_integration -- --nocapture
cargo fmt --check
```
