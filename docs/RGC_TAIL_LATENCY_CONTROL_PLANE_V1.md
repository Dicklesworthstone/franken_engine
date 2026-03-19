# RGC Tail Latency Control Plane V1

Primary bead: `bd-1lsy.7.11`

This document defines the parent integration surface for the compositional
tail-latency control plane. The shipped child subsystems remain:

- `bd-1lsy.7.11.1`: stage-envelope certificates
- `bd-1lsy.7.11.2`: queueing admission control
- `bd-1lsy.7.11.3`: bounded feedback control

The parent `RGC-611` surface composes those child artifacts into one
deterministic bundle so operators can inspect end-to-end p99/p999 behavior
without losing the queue/service/synchronization/GC decomposition.

## Artifact Contract

`scripts/run_rgc_tail_latency_control_plane.sh` emits:

- `latency_control_plane_report.json`
- `trace_ids.json`
- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `step_logs/step_000.log`
- `summary.md`
- `env.json`
- `repro.lock`

`latency_control_plane_report.json` must contain:

- per-stage envelope bundle and violation reports
- queue-model calibration for each modeled stage
- end-to-end budget and observed p99/p999 bounds
- explicit queue, service, synchronization, and GC decomposition
- runtime guardrail state, including fallback activation when breached

## Verification

Heavy execution must stay on `rch`:

```bash
./scripts/run_rgc_tail_latency_control_plane.sh ci
./scripts/e2e/rgc_tail_latency_control_plane_replay.sh ci
RGC_TAIL_LATENCY_CONTROL_PLANE_PROFILE=balanced \
  ./scripts/run_rgc_tail_latency_control_plane.sh ci
```

The synthetic contention profile is expected to engage fallback guardrails.
That is a feature of the stress artifact, not a test failure.

The balanced profile is expected to stay nominal with
`guardrails.fallback_activated == false`.
