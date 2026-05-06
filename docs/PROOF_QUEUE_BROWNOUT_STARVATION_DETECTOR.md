# Proof Queue Brownout Starvation Detector

`scripts/proof_queue_brownout_starvation_detector.sh` detects proof-queue
brownout, starvation, and unfair scheduling patterns from fixture replay
artifacts.

The detector consumes `franken-engine.proof-economy-replay-trace.v1` and can
also consume `franken-engine.proof-economy-counterfactual-replay-report.v1`.
It does not query live workers, mutate `rch`, or run proof commands.

## Usage

```bash
./scripts/proof_queue_brownout_starvation_detector.sh \
  --replay-trace-json /tmp/proof-economy/replay_trace.normalized.json \
  --counterfactual-report-json /tmp/proof-economy-counterfactual/counterfactual_replay_report.json \
  --output-dir /tmp/proof-queue-brownout
```

## Findings

The detector emits `franken-engine.proof-queue-brownout-report.v1` with:

- `queue_brownout_all_workers_busy`: fail-closed receipt when every replayed
  proof command reports a busy, queued, or deferred lease decision.
- `unfair_agent_slot_share`: warning when one agent owns more than the
  configured proof queue share.
- `low_priority_starvation`: warning when counterfactual policy defers broad
  low-priority proof work; the finding includes bounded remediation text.
- `counterfactual_all_policies_brownout`: fail-closed receipt when every
  counterfactual policy has no scheduled commands or fails closed.

## Artifacts

Each run emits:

- `brownout_report.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

## Validation

```bash
bash -n scripts/proof_queue_brownout_starvation_detector.sh
bash -n scripts/e2e/proof_queue_brownout_starvation_detector_smoke.sh
bash scripts/e2e/proof_queue_brownout_starvation_detector_smoke.sh check
bash scripts/e2e/proof_queue_brownout_starvation_detector_smoke.sh selftest
```
