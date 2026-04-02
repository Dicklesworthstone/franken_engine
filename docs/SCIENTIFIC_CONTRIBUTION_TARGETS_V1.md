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

## Technical Report Catalog

`bd-2501.1` now uses a dedicated report-catalog surface to make the
"publishable technical reports" milestone more machine-checkable instead of
leaving it as a prose-only threshold.

Catalog surfaces:

- `docs/SCIENTIFIC_REPORT_CATALOG_V1.md`
- `docs/scientific_report_catalog_v1.json`

The catalog currently tracks four report lanes:

1. probabilistic guardplane and observability-on publication policy
2. security-enforcement adversarial verification
3. runtime-semantics verification with replay evidence
4. extension-heavy benchmark methodology and peer-comparison posture

The Section 16 runner emits `technical_report_status_report.json` so operators
can see which report lanes are already documentation-complete versus still
blocked on open status beads or missing publication surfaces.

## External Replication Catalog

`bd-2501.2` now uses a dedicated external-replication catalog surface to make
the "externally replicated high-impact claims" milestone auditable before the
milestone itself closes.

Catalog surfaces:

- `docs/EXTERNAL_REPLICATION_CATALOG_V1.md`
- `docs/external_replication_catalog_v1.json`

The catalog currently tracks three candidate external-rerun lanes:

1. extension-heavy benchmark peer-claim bundles
2. security-enforcement verifier bundles
3. runtime-semantics replay/receipt verifier bundles

The Section 16 runner emits `external_replication_status_report.json` so
operators can distinguish claim lanes that are verifier-ready from claim lanes
that are still blocked on open implementation beads or missing verifier
surfaces.

## Open Tool Adoption Catalog

`bd-2501.3` now uses a dedicated open-tool adoption catalog surface so the
"open benchmark or verification tool adopted outside the project" milestone is
not left as prose-only intent.

Catalog surfaces:

- `docs/OPEN_TOOL_ADOPTION_CATALOG_V1.md`
- `docs/open_tool_adoption_catalog_v1.json`

The catalog currently tracks three candidate release lanes:

1. the `franken-verify` third-party verifier toolkit
2. the extension-heavy benchmark suite publication surface
3. the parser third-party rerun kit

The Section 16 runner emits `open_tool_adoption_status_report.json` so
operators can distinguish tool lanes that are release-ready from tool lanes
that still lack explicit external-adoption evidence.

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
- `technical_report_status_report.json`
- `external_replication_status_report.json`
- `open_tool_adoption_status_report.json`
- `scientific_contribution_summary.md`
- `scientific_contribution_targets_v1.json`
- `scientific_contribution_targets_v1.md`
- `scientific_report_catalog_v1.json`
- `SCIENTIFIC_REPORT_CATALOG_V1.md`
- `external_replication_catalog_v1.json`
- `EXTERNAL_REPLICATION_CATALOG_V1.md`
- `open_tool_adoption_catalog_v1.json`
- `OPEN_TOOL_ADOPTION_CATALOG_V1.md`
- `step_logs/step_*.log`

## README Surface Contract

The machine-readable contract in
`docs/scientific_contribution_targets_v1.json` also pins the operator-facing
README surface through `required_readme_fragments`.

Those fragments are intentionally narrow and must continue to cover:

- the `Scientific Contribution Targets Gate` heading,
- the bundle, `ci`, and replay commands,
- the report/replication/tool-adoption catalog references,
- the emitted artifact path surface, and
- the `rch`-backed operator verification target directory.

If the README stops surfacing those fragments, the Rust contract test must fail
closed so Section 16 operator guidance cannot silently drift away from the
machine-readable gate contract.

## Operator Verification

This bundle currently fails closed because the output-contract milestone beads
remain open. That fail-closed status is expected until `bd-2501.1`,
`bd-2501.2`, and `bd-2501.3` close.

```bash
jq empty docs/scientific_contribution_targets_v1.json
jq empty docs/scientific_report_catalog_v1.json
jq empty docs/external_replication_catalog_v1.json
jq empty docs/open_tool_adoption_catalog_v1.json
./scripts/run_scientific_contribution_targets.sh bundle
./scripts/e2e/scientific_contribution_targets_replay.sh show
rch exec -- env RUSTUP_TOOLCHAIN=nightly CARGO_TARGET_DIR=$PWD/target_rch_scientific_contribution_targets_verify CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p frankenengine-engine --test scientific_contribution_targets
```
