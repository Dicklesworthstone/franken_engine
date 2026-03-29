# RGC NPM Compatibility Matrix V1

Status: active
Primary bead: bd-1lsy.5.4
Track id: RGC-404
Machine-readable contract: `docs/rgc_npm_compatibility_matrix_v1.json`

## Purpose

`RGC-404` makes npm compatibility claims explicit, deterministic, and
fail-closed. The shipped lane exists so package-cohort truth is backed by a
replayable artifact bundle instead of anecdotal ecosystem compatibility claims.

The matrix records:

- deterministic cohort selection
- per-package compatibility outcomes
- minimized repros for unresolved failures
- root-cause classification
- owner routing via `owner` and `related_beads`
- a matrix verdict over the shipped cohorts

## Seed Cohorts And Verdict Surface

The shipped seed matrix covers:

- `tier_1_critical`
- `tier_2_popular`
- `tier_3_long_tail`

The direct matrix module classifies package outcomes as:

- `compatible`
- `partially_compatible`
- `incompatible`
- `skipped`
- `untested`

The verdict surface is:

- `all_cohorts_unblocked`
- `partially_unblocked`
- `blocked`
- `insufficient_data`

Every unresolved failure must retain a deterministic `incompatibility_id`,
`minimized_repro`, `root_cause`, `owner`, `related_beads`, and remediation
state so follow-up work can be routed without manual log archaeology.

## Shipped Surfaces

The direct writer surface is:

```bash
franken_npm_compatibility_matrix --out-dir <DIR>
```

Heavy validation and bundle emission run through the shipped `rch`-backed
wrapper:

```bash
./scripts/run_rgc_npm_compatibility_matrix.sh ci
```

The replay wrapper is:

```bash
./scripts/e2e/rgc_npm_compatibility_matrix_replay.sh ci
```

Exact preserved-run replay is supported through:

```bash
RGC_NPM_COMPATIBILITY_MATRIX_REPLAY_RUN_DIR=artifacts/rgc_npm_compatibility_matrix/<UTC_TIMESTAMP> \
  ./scripts/e2e/rgc_npm_compatibility_matrix_replay.sh ci
```

The replay wrapper resolves the latest complete run directory, warns when it
has to skip a newer incomplete directory, and fails closed on incomplete
explicit run directories.

## Artifact Contract

Gate runs emit artifacts under:

`artifacts/rgc_npm_compatibility_matrix/<UTC_TIMESTAMP>/`

with:

- `npm_compat_matrix_report.json`
- `trace_ids.json`
- `run_manifest.json`
- `events.jsonl`
- `commands.txt`

`npm_compat_matrix_report.json` is the human-readable and machine-readable
summary surface. It includes `cohort_summaries`, `root_cause_distribution`,
`top_blockers`, `packages`, and `unresolved_failures`.

## Operator Verification

```bash
jq empty docs/rgc_npm_compatibility_matrix_v1.json

./scripts/run_rgc_npm_compatibility_matrix.sh ci

cat artifacts/rgc_npm_compatibility_matrix/<UTC_TIMESTAMP>/npm_compat_matrix_report.json
cat artifacts/rgc_npm_compatibility_matrix/<UTC_TIMESTAMP>/trace_ids.json
cat artifacts/rgc_npm_compatibility_matrix/<UTC_TIMESTAMP>/run_manifest.json
cat artifacts/rgc_npm_compatibility_matrix/<UTC_TIMESTAMP>/events.jsonl
cat artifacts/rgc_npm_compatibility_matrix/<UTC_TIMESTAMP>/commands.txt
jq '.unresolved_failures' artifacts/rgc_npm_compatibility_matrix/<UTC_TIMESTAMP>/npm_compat_matrix_report.json

RGC_NPM_COMPATIBILITY_MATRIX_REPLAY_RUN_DIR=artifacts/rgc_npm_compatibility_matrix/<UTC_TIMESTAMP> \
  ./scripts/e2e/rgc_npm_compatibility_matrix_replay.sh ci
```
