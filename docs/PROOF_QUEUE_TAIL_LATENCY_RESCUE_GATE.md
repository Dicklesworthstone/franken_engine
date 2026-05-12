# Proof Queue Tail-Latency Rescue Gate

Bead: `bd-ciutb`

`scripts/proof_queue_tail_latency_rescue_gate.sh` consumes preserved proof queue
replay evidence and emits an advisory-only tail-latency rescue receipt. It reuses
`scripts/proof_queue_brownout_starvation_detector.sh` and keeps the detector
artifacts under `brownout_detector/`.

The gate never mutates live workers, br, Agent Mail, reservations, or queue
policy. It does not run Cargo or invoke rch. It only evaluates preserved JSON
evidence.

## Usage

```bash
./scripts/proof_queue_tail_latency_rescue_gate.sh \
  --replay-trace-json /path/to/replay_trace.normalized.json \
  --counterfactual-report-json /path/to/counterfactual_replay_report.json \
  --tail-latency-report-json /path/to/latency_control_plane_report.json \
  --max-agent-share-millionths 500000 \
  --output-dir /tmp/proof-queue-tail-latency-rescue
```

## Artifacts

- `run_manifest.json`
- `tail_latency_rescue_receipt.json`
- `events.jsonl`
- `commands.txt`
- `report.md`
- `brownout_detector/brownout_report.json`

## Detection Coverage

The receipt maps the detector findings into bounded recommendations:

- `queue_brownout_all_workers_busy` -> pause broad proof fanout.
- `unfair_agent_slot_share` -> limit the monopolizing agent to one heavy lane.
- `low_priority_starvation` -> bound P3 deferral and retry only after protected work drains.
- `counterfactual_all_policies_brownout` -> stop admitting new heavy proof work until capacity is refreshed.

Every recommendation records the cause, affected agents, affected beads,
fairness evidence, and proposed bounded action. Actions remain advisory and
declare `mutates_live_state: false`.

## Validation

```bash
jq empty docs/proof_queue_tail_latency_rescue_gate_contract_v1.json scripts/testdata/proof_queue_tail_latency_rescue_gate/cases.json
bash -n scripts/proof_queue_tail_latency_rescue_gate.sh scripts/e2e/proof_queue_tail_latency_rescue_gate_smoke.sh
shellcheck -x scripts/proof_queue_tail_latency_rescue_gate.sh scripts/e2e/proof_queue_tail_latency_rescue_gate_smoke.sh
bash scripts/e2e/proof_queue_brownout_starvation_detector_smoke.sh check
bash scripts/e2e/proof_queue_brownout_starvation_detector_smoke.sh selftest
bash scripts/e2e/proof_queue_tail_latency_rescue_gate_smoke.sh check
bash scripts/e2e/proof_queue_tail_latency_rescue_gate_smoke.sh selftest
git diff --check -- scripts/proof_queue_tail_latency_rescue_gate.sh scripts/e2e/proof_queue_tail_latency_rescue_gate_smoke.sh scripts/testdata/proof_queue_tail_latency_rescue_gate/cases.json docs/proof_queue_tail_latency_rescue_gate_contract_v1.json docs/PROOF_QUEUE_TAIL_LATENCY_RESCUE_GATE.md
```
