# Scientific Contribution Targets V1

## Purpose

`bd-2501` is the Section 16 strategy bead that turns FrankenEngine's
scientific-contribution obligations into an auditable status bundle.

This document is intentionally self-contained:

- it maps each required contribution to the concrete closed bead that satisfies
  it,
- it maps each Section 16 output-contract threshold to the status bead that
  still has to close before the umbrella can close, and
- it names the upstream evidence dependencies that keep the claims externally
  defensible.

As of 2026-03-21:

1. every required contribution listed below is backed by a closed bead,
2. every upstream dependency listed below is backed by a closed bead, but
3. the output-contract milestone beads `bd-2501.1`, `bd-2501.2`, and
   `bd-2501.3` remain open.

That means the Section 16 strategy is evidence-backed but not yet ready to
close.

## Required Contributions

### 1. Open specifications

- Strategy intent: publish core trust, replay, and policy primitives as open
  technical specifications that third parties can inspect and adopt.
- Delivery bead: `bd-3ebk`
- User outcome: the trust/replay/policy core is externally legible rather than
  project-private.

### 2. Reproducible datasets

- Strategy intent: make incident replay and adversarial evaluation results
  reproducible as datasets rather than screenshots or anecdotes.
- Delivery bead: `bd-2pwr`
- User outcome: external verifiers can rerun the same replay and adversarial
  evidence corpus deterministically.

### 3. Reference proofs and proof sketches

- Strategy intent: document key safety claims with proof-oriented artifacts
  instead of leaving them as prose assurances.
- Delivery bead: `bd-16up`
- User outcome: policy and protocol safety claims can be reviewed with explicit
  proof scaffolding.

### 4. External evaluations

- Strategy intent: validate claims through published red-team or academic-style
  methodologies instead of internal-only signoff.
- Delivery bead: `bd-52ko`
- User outcome: external reviewers can inspect methodology and reproduce the
  evaluation posture.

### 5. Public technical reports

- Strategy intent: publish reports covering failures, fixes, and frontier
  movement instead of reporting successes only.
- Delivery bead: `bd-2cc8`
- User outcome: scientific contribution claims carry an auditable paper trail
  with negative-result context.

## Output Contract Milestones

The Section 16 umbrella is not considered complete until the following
milestone beads close:

### 1. Publish reproducible technical reports

- Status bead: `bd-2501.1`
- Supporting closed bead: `bd-2zk0`
- Threshold: at least 4 publishable technical reports with reproducible
  artifact bundles.

### 2. Achieve externally replicated claims

- Status bead: `bd-2501.2`
- Supporting closed bead: `bd-3c8n`
- Threshold: at least 2 externally replicated high-impact claims.

### 3. Release an adopted open benchmark or verification tool

- Status bead: `bd-2501.3`
- Supporting closed bead: `bd-37cc`
- Threshold: at least 1 open benchmark or verification tool adopted outside the
  project.

The supporting closed beads show that the detailed Section 16 obligations were
consolidated and historically satisfied, but the active milestone beads are the
closure surface for `bd-2501`. The strategy bundle therefore fails closed until
those milestone beads are themselves closed.

## Upstream Dependencies

The Section 16 strategy only makes credible scientific claims when the
supporting evidence stack remains closed:

- `bd-19l0`: benchmark suite specification
- `bd-25b7`: PLAS benchmark bundle
- `bd-3ab3`: verifier pipeline for signatures, transparency, and attestations
- `bd-3gsv`: third-party verifier toolkit
- `bd-f7n`: beyond-parity category-shift report
- `bd-3rd`: adversarial campaign release gate
- `bd-1ze`: Node/Bun comparison harness with publishable methodology

If any of those reopen, Section 16 must fail closed because its research and
publication claims would no longer rest on closed evidence.

## Closure Semantics

Closing `bd-2501` means:

- all five required contribution families are backed by closed delivery beads,
- all three output-contract milestone beads are closed, and
- all upstream dependencies remain closed.

Closing `bd-2501` does not imply that the entire master program is complete.
The parent Section 16 epic `bd-esst` and broader program epics still track
cross-section dependencies and remaining master-program closure work.

## Bundle Artifacts

The validation bundle produced by the runner lives under:

`artifacts/scientific_contribution_targets/<UTC_TIMESTAMP>/`

Required artifacts:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `trace_ids.json`
- `contribution_status_report.json`
- `output_contract_status_report.json`
- `dependency_status_report.json`
- `scientific_contribution_summary.md`
- `scientific_contribution_targets_v1.json`
- `scientific_contribution_targets_v1.md`
- `step_logs/step_*.log`

## Operator Verification

This bundle currently fails closed because the output-contract milestone beads
remain open. That fail-closed status is expected until `bd-2501.1`,
`bd-2501.2`, and `bd-2501.3` close.

```bash
jq empty docs/scientific_contribution_targets_v1.json
./scripts/run_scientific_contribution_targets.sh bundle
./scripts/e2e/scientific_contribution_targets_replay.sh show
rch exec -- env RUSTUP_TOOLCHAIN=nightly CARGO_TARGET_DIR=$PWD/target_rch_scientific_contribution_targets_verify CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p frankenengine-engine --test scientific_contribution_targets
```
