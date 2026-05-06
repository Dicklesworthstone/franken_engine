# RCH Worker Truth Parity Ledger

`scripts/rch_worker_truth_parity_ledger.sh` is a shell-first, fail-closed
reconciliation tool for remote-proof worker state. It combines the `rch` daemon
worker view, probe or capability snapshots, queue diagnostics, and incident
evidence into one deterministic contract so operators do not have to trust one
surface in isolation.

## Purpose

The ledger exists to catch the exact drift patterns that have repeatedly made
remote-proof lanes look healthier than they really are:

- a worker looks idle or schedulable in probe output, but the daemon no longer
  reports it as healthy
- the daemon says a worker is healthy, but probes or capability checks no
  longer agree
- queue diagnostics keep a drained worker in circulation after the daemon view
  dropped it
- a build is marked completed or canceled, but incident evidence still shows a
  live remote compile

When any of those conditions appear, the ledger returns a fail-closed verdict.

## Usage

```bash
./scripts/rch_worker_truth_parity_ledger.sh \
  --daemon-workers-json artifacts/rch/workers_list.json \
  --probe-workers-json artifacts/rch/workers_probe.json \
  --queue-diagnostics-json artifacts/rch/queue_diag.json \
  --incident-packet-json artifacts/rch/incident_packet.json \
  --output-dir /tmp/rch-worker-truth-parity
```

Required inputs:

- `--daemon-workers-json`: `rch` daemon worker-state snapshot
- `--probe-workers-json`: probe or capability snapshot that expresses whether a
  worker is actually schedulable

Optional inputs:

- `--queue-diagnostics-json`: selector or queue evidence, including
  per-worker schedulability and `drained_workers`
- `--incident-packet-json`: incident classification bundle such as the output
  from `scripts/rch_incident_packet_gate.sh`

## Contract

The ledger emits `worker_truth_report.json` with schema version
`franken-engine.rch-worker-truth-parity-report.v1`.

Top-level fields:

- `decision`: `pass` or `fail_closed`
- `queue_snapshot_status`: `provided` or `missing`
- `incident_snapshot_status`: `provided` or `missing`
- `daemon_worker_count`, `probe_worker_count`, `queue_worker_count`
- `drift_count`
- `ghost_job_detected`
- `queue_decision`, `queue_reason`
- `worker_rows[]`
- `findings[]`
- `incident_evidence`
- `artifact_paths`

Each `worker_rows[]` entry records:

- `worker_id`
- daemon presence, status, and drained state
- probe presence, status, and schedulability
- queue presence, schedulability, and selection reason
- row-local findings

Finding codes currently emitted:

- `healthy_probe_absent_or_unschedulable_in_daemon`
- `healthy_daemon_absent_or_unschedulable_in_probe`
- `selector_drift_probe_schedulable_queue_blocked`
- `drained_worker_missing_from_daemon`
- `ghost_job_live_remote_compile`

## Artifacts

Every run emits deterministic artifacts:

- `worker_truth_report.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

`commands.txt` captures the exact invocation. `events.jsonl` provides a
machine-readable lifecycle trace. `report.md` is a concise human summary.

## Proof

The smoke harness is `scripts/e2e/rch_worker_truth_parity_ledger_smoke.sh`.
Its required fixtures are:

- healthy idle-and-schedulable parity
- fail-closed snapshot-parity drift
- fail-closed drained-worker disappearance
- fail-closed ghost-job evidence

Run:

```bash
./scripts/e2e/rch_worker_truth_parity_ledger_smoke.sh check
./scripts/e2e/rch_worker_truth_parity_ledger_smoke.sh selftest
```
