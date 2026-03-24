# RGC Observability Publication Policy V1

Status: active
Primary bead: bd-1lsy.11.20.3
Track id: RGC-066C
Machine-readable contract: `docs/rgc_observability_publication_policy_v1.json`

## Purpose

`RGC-066C` makes observability-on publication explicit, deterministic, and
fail-closed. The lane exists so performance and rollout claims cannot hide the
cost of shipped telemetry behind observability-off lab runs.

The publication bundle composes:

- calibration-sentinel quality evidence
- observability-on supremacy-cell decisions
- hot-path calibration and thinning summaries
- claim-delta reports across capture modes
- telemetry demotion receipts
- support-bundle observability attestation

## Workload Classes And Capture Modes

The shipped bundle covers three workload classes:

- `dispatch_sensitive`
- `hostcall_sensitive`
- `startup_sensitive`

Each workload is evaluated in three capture modes:

- `off`: never a publishable claim surface
- `budgeted`: default shipped mode and the baseline operator-facing claim mode
- `exact_shadow`: deterministic fallback/attestation mode when budgeted
  evidence is degraded or suppressed

`budgeted` is the default shipped capture mode for the publication policy and
support-bundle attestation surfaces.

## Publication Bundle Contract

The direct writer surface is:

```bash
franken_observability_publication_bundle --out-dir <DIR>
```

The bundle emits these JSON artifacts:

- `observability_budget_sentinel_report.json`
- `observability_on_supremacy_matrix.json`
- `observability_claim_delta_report.json`
- `telemetry_demotion_receipts.json`
- `observability_publication_policy.json`
- `support_bundle_observability_attestation.json`

The bundle hashes all emitted artifacts, produces a deterministic `bundle_hash`,
and carries the policy id `policy-rgc-observability-publication-v1`.

## Fail-Closed Publication Rules

The publication policy must suppress claims when any of these conditions hold:

- observability-off cells are used as the claim surface
- budgeted cells lack calibration-sentinel evidence
- exact-shadow fallback has not replaced degraded budgeted evidence
- the observability quality sentinel is degraded
- the hot-path telemetry manifest is not publishable
- one or more workload cells remain suppressed

Support-bundle export must carry explicit observability attestation so the
shipped capture mode and suppression state are visible without reconstructing
raw logs by hand.

## Structured Logging And Artifact Contract

Gate runs emit artifacts under:

`artifacts/rgc_observability_publication_policy/<UTC_TIMESTAMP>/`

with:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `trace_ids`
- `step_logs/`
- the six publication-bundle JSON artifacts listed above

Heavy validation must run through the shipped `rch`-backed wrapper:

```bash
./scripts/run_rgc_observability_publication_policy.sh ci
```

The replay wrapper is:

```bash
./scripts/e2e/rgc_observability_publication_policy_replay.sh ci
```

The replay wrapper resolves the latest complete artifact bundle, warns when it
has to skip a newer incomplete run directory, and supports exact preserved-run
inspection without rerunning the lane:

```bash
RGC_OBSERVABILITY_PUBLICATION_POLICY_REPLAY_RUN_DIR=artifacts/rgc_observability_publication_policy/<UTC_TIMESTAMP> \
  ./scripts/e2e/rgc_observability_publication_policy_replay.sh ci
```

## Operator Verification

```bash
jq empty docs/rgc_observability_publication_policy_v1.json

./scripts/run_rgc_observability_publication_policy.sh ci

cat artifacts/rgc_observability_publication_policy/<UTC_TIMESTAMP>/trace_ids
ls artifacts/rgc_observability_publication_policy/<UTC_TIMESTAMP>/step_logs
cat artifacts/rgc_observability_publication_policy/<UTC_TIMESTAMP>/step_logs/step-01.log

RGC_OBSERVABILITY_PUBLICATION_POLICY_REPLAY_RUN_DIR=artifacts/rgc_observability_publication_policy/<UTC_TIMESTAMP> \
  ./scripts/e2e/rgc_observability_publication_policy_replay.sh ci
```
