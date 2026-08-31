# Receipt-Bound Red-Team Repeated-Trial Harness

**Owning bead:** `bd-1vwza`  
**Claim:** `FE-CLAIM-011`  
**Current claim state:** **TARGETED**

This document defines the operator and contributor contract for measuring the
successful host-compromise rate of the same declared adversarial scenarios under
Node, Bun, and FrankenEngine. The producer emits the existing
`franken-engine.red-team-harness-output.v1` schema consumed by the Rust
`red_team_compromise_rate_metric_gate` module.

The existence of this harness does not promote `FE-CLAIM-011`. Promotion still
requires a current, exact-revision, non-fixture campaign with at least 100
receipt-bound attempts per runtime and scenario, preservation of the complete
bundle, and a linked verification command.

## Honest Work Declaration

- **Consumer:** operators evaluating `FE-CLAIM-011`, the
  `franken_red_team_harness_gate` CLI, and the
  `red_team_compromise_rate_metric_gate` Rust module.
- **Executable gate:**
  `scripts/e2e/red_team_repeated_trial_harness_smoke.sh` exercises the 100-trial
  shape and tamper drills; `.github/workflows/main-safety.yml` runs that smoke on
  every direct commit; `.github/workflows/red-team-repeated-trial-gate.yml`
  checks the Rust conversion and decision path; and
  `.github/workflows/red-team-repeated-trial-measurement.yml` preserves a real
  operator-triggered campaign before enforcing its verdict.
- **Observed defect class:** the Rust contract and checked-in fixture already
  required `min_trials_per_runtime >= 100`, but the repository had only a
  single-attempt comparator. The documented
  `scripts/run_bd_28otw_attacker_harness.sh` producer did not exist, so no
  executable path could create the denominator accepted by the Rust gate.
- **Evolution condition:** this dedicated producer may be folded into a more
  general comparator-experiment framework only after the replacement preserves
  the same runtime identity pinning, per-attempt receipts, complete-matrix
  requirement, independent hash verification, replay behavior, and fail-closed
  blocker artifacts. Until then it remains the canonical FE-CLAIM-011 producer.

## System Shape

The harness deliberately separates four responsibilities:

1. `scripts/red_team_compromise_rate_metric.py` executes one complete
   Node/Bun/FrankenEngine scenario matrix and writes explicit, hash-bound runtime
   receipts.
2. `scripts/run_bd_28otw_attacker_harness.sh` repeats that complete matrix at
   least 100 times without treating a blocked probe as containment evidence.
3. `scripts/aggregate_red_team_trials.py` independently re-hashes every runtime
   executable, scenario script, manifest, witness, and transcript; enforces one
   immutable runtime/scenario matrix; then emits
   `franken-engine.red-team-harness-output.v1`.
4. `franken_red_team_harness_gate` deserializes that output through the product
   Rust types, converts it into the metric input, and applies the existing
   compromise-rate decision rule.

This layering prevents the shell producer from defining a second interpretation
of the metric. Python owns execution receipts and replay; Rust owns the product
metric contract and decision.

## Prerequisites

The normal producer requires executable Node, Bun, and `frankenctl` binaries.
The exact executable path, SHA-256 digest, version command, exit code, stdout,
and stderr are captured in every trial's `runtime_inventory.json`.

```bash
cargo build --release --no-default-features \
  -p frankenengine-engine \
  --bin frankenctl \
  --bin franken_red_team_harness_gate

export FRANKENENGINE_BIN="$PWD/target/release/frankenctl"
export NODE_BIN="$(command -v node)"
export BUN_BIN="$(command -v bun)"
```

A missing binary, timeout, malformed report, parser crash, ambiguous disposition,
or mismatched receipt produces a blocker bundle. None of those conditions count
as a contained attack.

## Run a Production-Shaped Campaign

```bash
revision="$(git rev-parse HEAD)"
run_id="manual-$(date -u +%Y%m%dT%H%M%SZ)"

./scripts/run_bd_28otw_attacker_harness.sh \
  --trials 100 \
  --artifact-root artifacts/red_team_repeated_trial_harness \
  --run-id "$run_id" \
  --code-revision "$revision" \
  --timeout-seconds 20
```

The production path refuses fewer than 100 trials. Hermetic tests may lower the
minimum only by explicitly setting
`RED_TEAM_HARNESS_ALLOW_TEST_MINIMUM=true`; evidence produced under that escape
hatch is not promotion evidence.

The operator-triggered GitHub Actions workflow pins Node `26.8.1` and Bun
`1.4.0`, builds the candidate and Rust evaluator at the dispatched commit, runs
100 complete trials by default, and uploads the entire evidence directory even
when the measured verdict is negative.

## Evaluate with the Rust Product Gate

```bash
harness_output="artifacts/red_team_repeated_trial_harness/$run_id/aggregate/harness_output.json"

./target/release/franken_red_team_harness_gate \
  --input "$harness_output" \
  --output "artifacts/red_team_repeated_trial_harness/$run_id/rust_metric_report.json" \
  --markdown "artifacts/red_team_repeated_trial_harness/$run_id/rust_metric_report.md"
```

Exit codes:

| Code | Meaning |
|---:|---|
| `0` | The harness input is valid and the measured metric passes its threshold. |
| `1` | The harness input is valid and the metric decision is fail-closed. |
| `2` | Usage, JSON, schema, denominator, conversion, or I/O failure. |

A metric pass is still only a measurement result. Claim promotion requires the
bundle to be preserved and linked from the authoritative claim-to-proof matrix.

## Replay and Narrow Verification

Replay recomputes the aggregate counts from the per-attempt dispositions and
re-hashes the aggregate plus every referenced source receipt.

```bash
./scripts/run_bd_28otw_attacker_harness.sh \
  --replay \
  --harness-output "$harness_output" \
  --trials 100
```

A focused replay is useful during incident triage:

```bash
./scripts/run_bd_28otw_attacker_harness.sh \
  --replay \
  --harness-output "$harness_output" \
  --scenario environment_variable_exfiltration \
  --runtime franken_engine \
  --trials 100
```

Filters are replay-only. A live campaign always executes the complete declared
scenario/runtime matrix so its denominator cannot be assembled from convenient
partial runs.

## Artifact Anatomy

For run directory `<run>`:

| Path | Question answered |
|---|---|
| `<run>/trials/trial-NNNN/runtime_inventory.json` | Which exact executables were measured? |
| `<run>/trials/trial-NNNN/transcripts/*.json` | What command ran, what did it emit, and what explicit disposition was derived? |
| `<run>/trials/trial-NNNN/witnesses/*.json` | Which script, manifest, and runtime receipts define one scenario attempt? |
| `<run>/trials/trial-NNNN/scenarios.jsonl` | Was the complete five-scenario matrix observed for this trial? |
| `<run>/aggregate/trial_index.jsonl` | Which trial bundles comprise the aggregate denominator? |
| `<run>/aggregate/transcripts/*.json` | What are the per-runtime/per-scenario attempt counts and source receipt links? |
| `<run>/aggregate/witnesses/*.json` | Which aggregate transcript and runtime identity are bound to each result? |
| `<run>/aggregate/measurement_details.json` | What exact inputs back the final harness rows? |
| `<run>/aggregate/harness_output.json` | What schema-valid input is consumed by the Rust metric gate? |
| `<run>/rust_metric_report.json` | What decision did the product Rust contract make? |

All persisted paths are repository-relative. Artifacts outside the repository
root are rejected because absolute, host-local references are not portable
replay evidence.

## Fail-Closed Conditions

The aggregator refuses, among other cases:

- fewer than 100 attempts for any runtime/scenario pair;
- a missing runtime or scenario in any individual trial;
- mixed code revisions or executable identities;
- changed script or manifest bytes during a campaign;
- placeholder, provisional, negative-fixture, or ambiguous rows;
- mismatched row/transcript dispositions;
- witness, transcript, executable, script, or manifest hash mismatch;
- aggregate counts that cannot be recomputed from source receipts; and
- replay filters that do not identify an emitted result.

On aggregation failure, `aggregation_blocker.json` records the reason,
remediation, and `placeholder_results_emitted: false`. The producer never fills
missing evidence with assumed Node/Bun outcomes or treats a runtime failure as a
successful containment result.

## Regression Gates

```bash
python3 -m py_compile \
  scripts/red_team_compromise_rate_metric.py \
  scripts/red_team_trial_common.py \
  scripts/red_team_trial_reader.py \
  scripts/aggregate_red_team_trials.py

bash scripts/e2e/red_team_compromise_rate_metric_comparator_smoke.sh
bash scripts/e2e/red_team_repeated_trial_harness_smoke.sh

cargo test --no-default-features -p frankenengine-engine \
  --bin franken_red_team_harness_gate
cargo test --no-default-features -p frankenengine-engine \
  --test red_team_harness_gate_cli
```

The synthetic repeated-trial smoke validates contract mechanics, not the
security metric. It creates 100 hash-bound fixture trials, proves successful
aggregation and replay, and then proves that aggregate tampering, source-receipt
tampering, and an insufficient denominator all fail closed.
