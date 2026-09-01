# Receipt-Bound Red-Team Scenario-Corpus Stability Harness

**Owning bead:** `bd-1vwza`  
**Claim:** `FE-CLAIM-011`  
**Current claim state:** **TARGETED**  
**Machine contract:** [`red_team_scenario_corpus_v2.json`](red_team_scenario_corpus_v2.json)

This document defines the operator and contributor contract for comparing the
successful host-compromise disposition of the same exact security-critical
scenario corpus under Node, Bun, and FrankenEngine.

The implementation path is now complete enough to execute and preserve a
contract-bound campaign, but that fact does **not** promote `FE-CLAIM-011`.
Promotion still requires a current, exact-revision, non-fixture live campaign,
a preserved complete bundle, a passing Rust claim verdict, and an authoritative
claim-matrix update linking that evidence.

## Critical Statistical Boundary

The denominator is the set of **distinct contract-declared adversarial
scenarios**. Repeating one deterministic scenario 100 times does not create 100
independent attack samples.

The 100 repetitions per runtime/scenario pair establish:

- disposition stability;
- receipt completeness;
- executable and scenario identity stability;
- deterministic replayability; and
- absence of one-off transient outcomes.

They do **not** establish population confidence, attack-distribution coverage,
or an empirical 1/100 compromise probability. Every artifact carries
`repetition_role: stability_and_replay_not_independent_sampling` and
`confidence_interpretation: receipt_completeness_and_stability_not_population_confidence`.

The Rust claim evaluator applies the metric to the distinct scenario corpus. A
zero observed FrankenEngine cell is guarded as one hypothetical compromised
scenario before threshold comparison. Therefore:

```text
conservative_reduction_floor =
    min(node_compromised_scenarios, bun_compromised_scenarios)
    / max(frankenengine_compromised_scenarios, 1)
```

This prevents a small zero-event corpus from manufacturing an infinite result.
A five-scenario all-baseline-compromised/zero-FrankenEngine-compromised result is
only a conservative `5x` floor and cannot satisfy the `>=10x` target. The
current contract deliberately contains ten distinct scenarios, making `10x` the
largest zero-cell-guarded floor available from this corpus.

## Authoritative Corpus V2

`docs/red_team_scenario_corpus_v2.json` is the single machine-readable source of
truth consumed by both Python and Rust. It fixes:

- corpus ID `red_team_security_critical_compromise_v2`;
- exactly ten scenario IDs and their attack-class mapping;
- runtime order `node`, `bun`, `franken_engine`;
- thirty required runtime/scenario pairs;
- 100 required stability repetitions per pair;
- the one-scenario zero-cell guard;
- receipt-only and aggregate-input-only verdict scopes; and
- `franken_red_team_harness_gate` as the sole claim-verdict producer.

The ten scenarios are:

| Scenario | Attack class |
|---|---|
| `environment_variable_exfiltration` | `ambient_authority_escape` |
| `process_privilege_surface_probe` | `ambient_authority_escape` |
| `prototype_pollution_capability_escape` | `prototype_pollution` |
| `shell_command_injection_package_script` | `ambient_authority_escape` |
| `supply_chain_backdoor_execution` | `supply_chain_execution` |
| `ambient_authority_via_globalthis` | `ambient_authority_escape` |
| `capability_shadowed_import` | `ambient_authority_escape` |
| `reflect_apply_authority_smuggling` | `ambient_authority_escape` |
| `typed_effect_laundering_downcast` | `ambient_authority_escape` |
| `smuggle_flow_via_unanalyzed_construct` | `ambient_authority_escape` |

A count-preserving substitute is not equivalent. Python and Rust both reject a
bundle that has ten rows but changes a scenario ID, remaps its attack class,
omits a runtime, duplicates a pair, or lies about the declared counts.

## Honest Work Declaration

- **Consumers:** operators evaluating `FE-CLAIM-011`, the
  `franken_red_team_harness_gate` CLI, the disruptive-floor metric gate, and
  claim/evidence reviewers.
- **Executable gates:**
  `.github/workflows/red-team-repeated-trial-gate.yml` validates the machine
  contract, Python producer chain, fail-closed proof-class drills, receipt and
  replay tamper drills, Rust formatting, and Rust CLI behavior.
  `.github/workflows/red-team-repeated-trial-measurement.yml` is the explicit
  live measurement workflow and preserves evidence before enforcing its
  verdict.
- **Observed defect class:** the earlier implementation repeated five
  deterministic scenarios 100 times, collapsed each pair to an `any success`
  boolean, and treated a zero FrankenEngine cell as an infinite ratio. That
  discarded the repeated denominator while still allowing the repetitions to
  create unjustified proof strength.
- **Deletion/evolution condition:** this dedicated path may be folded into a
  broader experiment framework only when the replacement preserves the exact
  corpus contract, proof-class separation, runtime/scenario receipt bindings,
  replay commands, zero-cell guard, sole-verdict-producer rule, and negative
  drills.

## System Shape

The canonical path separates five responsibilities:

1. `scripts/red_team_compromise_rate_metric.py` executes one complete
   Node/Bun/FrankenEngine matrix and writes explicit hash-bound runtime receipts.
2. `scripts/red_team_compromise_rate_corpus.py` replaces the legacy five-case
   inventory with the exact v2 machine-contract corpus and marks each local
   bundle as `single_repetition_receipt_only_not_claim_verdict` with
   `claim_verdict_eligible: false`.
3. `scripts/run_bd_28otw_attacker_harness.sh` executes the complete matrix at
   least 100 times. Blocked probes never become containment evidence.
4. `scripts/red_team_scenario_corpus_harness.py` verifies repetition scope,
   delegates receipt aggregation, rewrites replay commands to the scoped
   verifier, rebinds hashes, and emits an
   `aggregate_stability_input_only_not_claim_verdict` harness. Any semantic
   finalization error overwrites a stale local pass with `fail_closed`.
5. `franken_red_team_harness_gate` loads the same JSON contract through
   `include_str!`, validates exact corpus/runtime identity, computes the
   conservative scenario-corpus floor, and is the **only** component allowed to
   emit the claim verdict.

The generic `aggregate_red_team_trials.py` remains a lower-level receipt
aggregator and verifier. Its output is not, by itself, FE-CLAIM-011 evidence.

## Prerequisites

The live producer requires executable Node, Bun, and `frankenctl` binaries. The
exact executable path, SHA-256 digest, version command, exit code, stdout, and
stderr are captured in every repetition's `runtime_inventory.json`.

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
mismatched receipt, incomplete corpus, or changed executable/script/manifest
produces a blocker or fail-closed bundle. None of those conditions count as a
contained attack.

## Run a Production-Shaped Campaign

```bash
revision="$(git rev-parse HEAD)"
run_id="manual-$(date -u +%Y%m%dT%H%M%SZ)"

./scripts/run_bd_28otw_attacker_harness.sh \
  --trials 100 \
  --artifact-root artifacts/red_team_scenario_corpus_measurement \
  --run-id "$run_id" \
  --code-revision "$revision" \
  --timeout-seconds 20
```

`--trials` is retained for CLI compatibility, but it means stability/replay
repetitions. The production path refuses fewer than the contract's 100
repetitions. Hermetic tests may lower the minimum only with
`RED_TEAM_HARNESS_ALLOW_TEST_MINIMUM=true`; such output is not promotion
evidence.

The operator-triggered Actions workflow pins Node `26.8.1` and Bun `1.4.0`,
builds the exact candidate and Rust evaluator, copies the corpus contract and
its SHA-256 digest into the run directory, executes the complete campaign,
evaluates it through Rust, uploads the bundle even on failure, and only then
enforces the verdict.

## Evaluate with the Sole Rust Claim Gate

```bash
harness_output="artifacts/red_team_scenario_corpus_measurement/$run_id/aggregate/harness_output.json"

./target/release/franken_red_team_harness_gate \
  --input "$harness_output" \
  --output "artifacts/red_team_scenario_corpus_measurement/$run_id/claim_verdict.json" \
  --markdown "artifacts/red_team_scenario_corpus_measurement/$run_id/claim_verdict.md"
```

Exit codes:

| Code | Meaning |
|---:|---|
| `0` | The exact contract-bound input is valid and the conservative scenario-corpus floor meets the threshold. |
| `1` | The exact contract-bound input is valid but the measured decision fails closed. |
| `2` | Usage, JSON, schema, corpus identity, scope, denominator, conversion, or I/O failure. |

A metric pass remains only a revision- and environment-bound measurement result.
It does not promote the public claim until the full evidence bundle is preserved
and linked from the authoritative claim matrix.

## Replay and Narrow Verification

Replay recomputes aggregate counts from source dispositions and re-hashes the
aggregate plus every referenced repetition receipt.

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

Filters are replay-only. A live campaign always executes the complete contract
matrix; its denominator cannot be assembled from convenient partial runs.

## Artifact Anatomy

For run directory `<run>`:

| Path | Question answered |
|---|---|
| `<run>/red_team_scenario_corpus_v2.json` | Which exact corpus and proof semantics governed the measurement? |
| `<run>/red_team_scenario_corpus_v2.sha256` | Was the preserved contract modified? |
| `<run>/source_revision.txt` | Which exact FrankenEngine revision was measured? |
| `<run>/node_version.txt`, `<run>/bun_version.txt` | Which comparator releases were requested? |
| `<run>/trials/trial-NNNN/runtime_inventory.json` | Which exact executables were measured in this repetition? |
| `<run>/trials/trial-NNNN/repetition_scope.json` | Why is this local status receipt-only and ineligible as the claim verdict? |
| `<run>/trials/trial-NNNN/transcripts/*.json` | What command ran and what explicit disposition was derived? |
| `<run>/trials/trial-NNNN/witnesses/*.json` | Which script, manifest, and runtime receipts define one scenario repetition? |
| `<run>/trials/trial-NNNN/scenarios.jsonl` | Was the complete ten-scenario matrix observed in this repetition? |
| `<run>/aggregate/trial_index.jsonl` | Which repetition bundles comprise the stability input? |
| `<run>/aggregate/transcripts/*.json` | What are the per-pair repetition counts and source receipt links? |
| `<run>/aggregate/measurement_details.json` | Which exact source receipts back the aggregate rows? |
| `<run>/aggregate/harness_output.json` | What input-only, contract-bound schema is consumed by Rust? |
| `<run>/claim_verdict.json` | What conservative decision did the sole Rust claim gate make? |
| `<run>/claim_verdict.md` | Human-readable rendering of that same Rust verdict. |
| `<run>/campaign.*.log`, `<run>/rust_gate.*.log` | How did execution and evaluation fail or succeed? |

Persisted references are repository-relative. Absolute host-local references are
rejected because they are not portable replay evidence.

## Fail-Closed Conditions

The canonical path refuses, among other cases:

- fewer than 100 stability repetitions for any runtime/scenario pair;
- a missing runtime or scenario in any repetition;
- a count-preserving scenario substitution or attack-class remap;
- a typed `scenario_set` that disagrees with the corpus ID;
- a repetition or aggregate that claims verdict eligibility;
- a claim producer other than `franken_red_team_harness_gate`;
- mixed code revisions or executable identities;
- changed script or manifest bytes during a campaign;
- placeholder, provisional, negative-fixture, or ambiguous rows;
- mixed success/failure dispositions across repetitions for one pair;
- mismatched row/transcript dispositions;
- witness, transcript, executable, script, manifest, or contract hash mismatch;
- aggregate counts that cannot be recomputed from source receipts; and
- replay filters that do not identify an emitted result.

On aggregation failure, `aggregation_blocker.json` records the reason,
remediation, and `placeholder_results_emitted: false`. The scoped finalizer also
writes or overwrites `bundle_status.json` as `fail_closed`, so a lower-level
receipt aggregation pass cannot survive a later semantic failure as a stale
success.

## Regression Gates

```bash
python3 -m py_compile \
  scripts/red_team_compromise_rate_metric.py \
  scripts/red_team_scenario_corpus_contract.py \
  scripts/red_team_compromise_rate_corpus.py \
  scripts/red_team_trial_common.py \
  scripts/red_team_trial_reader.py \
  scripts/aggregate_red_team_trials.py \
  scripts/annotate_red_team_harness_semantics.py \
  scripts/red_team_scenario_corpus_harness.py \
  scripts/e2e/red_team_scenario_corpus_scope_smoke.py

bash -n scripts/run_bd_28otw_attacker_harness.sh
python3 scripts/e2e/red_team_scenario_corpus_scope_smoke.py
bash scripts/e2e/red_team_repeated_trial_harness_smoke.sh

cargo test --no-default-features -p frankenengine-engine \
  --bin franken_red_team_harness_gate
cargo test --no-default-features -p frankenengine-engine \
  --test red_team_harness_gate_cli
```

The Python scope smoke proves exact corpus mapping, proof-class separation, and
stale-pass overwrite. The larger hermetic receipt smoke proves 100-repetition
aggregation, replay, hash binding, and tamper rejection. Neither synthetic smoke
is security-metric evidence.
