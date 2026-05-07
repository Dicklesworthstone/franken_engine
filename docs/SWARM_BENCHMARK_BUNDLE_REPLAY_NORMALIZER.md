# SWARM_BENCHMARK_BUNDLE_REPLAY_NORMALIZER

`bd-xn71h` defines the fixture-fed benchmark bundle normalizer for
SWARM-BENCH-I.

This surface exists because the benchmark workload catalog only tells operators
which benchmark surface answers which question. Operators still need one
advisory bundle that can line up benchmark run manifests, event logs,
throughput-baseline truth, and optional remote-stall receipts without
pretending that blocked or contaminated evidence is a real pass.

The normalizer is advisory only and proof only. It does not query live `br`,
Agent Mail, RCH, git, cargo, or workers. It does not mutate beads, release
reservations, send mail, or change queue policy.

## Request Contract

The normalizer consumes a checked-in or generated request JSON:

```json
{
  "schema_version": "franken-engine.swarm-benchmark-bundle-replay-normalizer.request.v1",
  "source_manifest_json": "docs/swarm_benchmark_workload_catalog_contract_v1.json",
  "evidence_rows": [
    {
      "workload_id": "extension_heavy_benchmark_spec",
      "evidence_kind": "run_manifest",
      "primary_artifact_json": "artifacts/extension_heavy_benchmark_spec/<timestamp>/run_manifest.json",
      "events_jsonl": "artifacts/extension_heavy_benchmark_spec/<timestamp>/extension_heavy_benchmark_spec_events.jsonl",
      "stall_bundle_json": null
    },
    {
      "workload_id": "frankenengine_throughput_baseline_status",
      "evidence_kind": "throughput_baselines",
      "primary_artifact_json": "docs/throughput_baseline_measurements_v1.json",
      "events_jsonl": null,
      "stall_bundle_json": null
    }
  ]
}
```

Supported `evidence_kind` values:

- `run_manifest`
- `throughput_baselines`

Paths may be absolute or repo-relative to `--workspace-root`.

## Outputs

The normalizer emits:

- `swarm_benchmark_bundle.json`
- `benchmark_findings.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

`swarm_benchmark_bundle.json` contains one normalized row per workload plus a
top-level decision.

## Row Semantics

Each normalized row resolves to one of these states:

- `observed`
- `blocked`
- `blocked_remote_validation`
- `recovered_remote_stall`
- `fail_closed`

Interpretation:

- `observed`: the preserved benchmark artifact is an explicit observed result.
- `blocked`: the preserved artifact truthfully says the workload is blocked.
- `blocked_remote_validation`: the workload failed and its remote-stall receipt
  is itself blocked evidence, so the normalizer preserves the blockage without
  inventing a pass.
- `recovered_remote_stall`: the workload failed, but a confirmed or degraded
  remote-stall receipt explains the failure without claiming benchmark success.
- `fail_closed`: contradictory, contaminated, malformed, or placeholder
  evidence was detected.

## Fail-Closed Rules

The normalizer must fail closed when:

- an evidence row names a workload id absent from the source manifest
- duplicate workload ids appear in the request
- required primary identifiers are missing from the evidence
- a referenced JSON artifact is malformed
- an observed manifest is paired with a blocked or stall-only receipt
- a stall receipt reports `local_fallback_observed: true`
- a blocked FrankenEngine throughput row still publishes placeholder ops/sec or
  fake workload results

Placeholder throughput claims are never accepted. A blocked runtime with
non-zero `baseline_ops_per_second` or non-empty `workload_results` is treated
as contaminated evidence.

## Decision Semantics

- `pass`: every workload row is `observed`
- `degraded`: no fail-closed violations occurred, but at least one row is
  `blocked`, `blocked_remote_validation`, or `recovered_remote_stall`
- `fail_closed`: at least one row is contradictory, malformed, contaminated, or
  missing primary identity

## Validation

For this bead:

```bash
bash -n scripts/swarm_benchmark_bundle_replay_normalizer.sh
bash -n scripts/e2e/swarm_benchmark_bundle_replay_normalizer_smoke.sh
shellcheck -x scripts/swarm_benchmark_bundle_replay_normalizer.sh scripts/e2e/swarm_benchmark_bundle_replay_normalizer_smoke.sh
jq empty scripts/testdata/swarm_benchmark_bundle_replay_normalizer/cases.json
bash scripts/e2e/swarm_benchmark_bundle_replay_normalizer_smoke.sh check
bash scripts/e2e/swarm_benchmark_bundle_replay_normalizer_smoke.sh selftest
git diff --check -- docs/SWARM_BENCHMARK_BUNDLE_REPLAY_NORMALIZER.md scripts/swarm_benchmark_bundle_replay_normalizer.sh scripts/e2e/swarm_benchmark_bundle_replay_normalizer_smoke.sh scripts/testdata/swarm_benchmark_bundle_replay_normalizer/cases.json
```
