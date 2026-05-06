# Proof Economy Replay Trace Normalizer

`scripts/proof_economy_replay_trace_normalizer.sh` normalizes fixture snapshots
for the SWARM-CTRL-VII scheduler replay lab into
`franken-engine.proof-economy-replay-trace.v1`.

The normalizer is fixture-only. It does not query live `br`, Agent Mail, `rch`,
or worker state. It exists so later replay and policy-evaluation surfaces can
share one canonical view of agents, beads, reservations, commands, and proof
artifacts.

## Usage

```bash
./scripts/proof_economy_replay_trace_normalizer.sh \
  --br-ready-json ready.json \
  --br-in-progress-json in_progress.json \
  --agent-mail-reservations-json reservations.json \
  --resource-lease-plans-json resource_leases.json \
  --proof-cache-plan-json proof_cache_plan.json \
  --resident-bundle-report-json resident_bundle_report.json \
  --no-mock-drill-report-json resident_remote_proof_no_mock_drill_report.json \
  --output-dir /tmp/proof-economy-replay-trace
```

## Inputs

Required inputs:

- `--br-ready-json`
- `--br-in-progress-json`

Optional inputs:

- `--agent-mail-reservations-json`
- `--resource-lease-plans-json`
- `--proof-cache-plan-json`
- `--resident-bundle-report-json`
- `--no-mock-drill-report-json`
- `--source-revision`
- `--output-dir`

Missing Agent Mail reservations are explicit degraded mode, not silent success.
The emitted trace sets `degraded_mode = true` and includes a
`missing_agent_mail_reservations` finding.

## Artifacts

Each run emits:

- `replay_trace.normalized.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The trace includes sorted `agents`, `bead_rows`, `reservation_rows`,
`command_rows`, and `proof_rows`. Duplicate proof artifacts are deduplicated by
artifact path plus artifact id before the stable `trace_id` hash is computed.

## Validation

```bash
bash -n scripts/proof_economy_replay_trace_normalizer.sh
bash -n scripts/e2e/proof_economy_replay_trace_normalizer_smoke.sh
bash scripts/e2e/proof_economy_replay_trace_normalizer_smoke.sh check
bash scripts/e2e/proof_economy_replay_trace_normalizer_smoke.sh selftest
```
