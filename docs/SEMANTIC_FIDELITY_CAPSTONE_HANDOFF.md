# Semantic Fidelity Capstone Handoff

Status: capstone evidence for `bd-mihky.10`

This handoff records the first semantic-fidelity truth-gate run over the seeded
RangeError and ToIntegerOrInfinity suite. It is scoped evidence for the
`bd-mihky` workbench and for E7/conformance-frontier consumers. It does not
claim complete ECMAScript conformance and does not promote any README or
claim-to-proof matrix wording.

## Evidence Bundle

Bundle:
`artifacts/semantic_fidelity_workbench_gate/bd-mihky-10-capstone-20300101T000000Z`

Suite:
`scripts/testdata/semantic_fidelity_workbench/rangeerror_tointeger_suite.json`

Manifest facts:

| Field | Value |
| --- | --- |
| `suite_id` | `semfid-suite-rangeerror-tointeger-v1` |
| `suite_sha256` | `sha256:e730923d9f91db98d243d3bb554ca4288604b5f9660d71de1ce3b533279c3e77` |
| `decision` | `supported_with_non_passing_vectors` |
| `generated_at_utc` | `2030-01-01T00:00:00Z` |
| `validation_errors` | `[]` |

Required bundle files were produced:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `vector_results.jsonl`
- `path_parity_report.json`
- `auto_triage_report.json`
- `summary.md`

## Gate Result

The capstone result is intentionally not a release-level OBSERVED claim. The
runner accepted the bundle because all executable oracle rows passed and the
non-executed engine rows were explicitly declared as expected-unknown.

| Measure | Count |
| --- | ---: |
| Vector results | 13 |
| Passed rows | 13 |
| Failed rows | 0 |
| Accepted external-oracle rows | 11 |
| Declared non-execution rows | 2 |
| Confirmed failures in auto-triage | 0 |
| Suggested new beads | 0 |
| Degraded surfaces | 0 |
| Unsupported/expected-unknown surfaces | 2 |

The two declared non-execution rows are:

| Vector | Route | Owner link |
| --- | --- | --- |
| `semfid-engine-source-eval-array-length-fractional-expected-unknown` | `engine.source-eval.array-length-fractional-assignment` | `bd-mihky.6` |
| `semfid-engine-source-eval-string-from-code-point-high-expected-unknown` | `engine.source-eval.string-from-code-point-high` | `bd-mihky.6` |

These rows are not silent semantic drift. They are recorded as
`declared_non_execution` with reason `engine_route_not_executed_by_runner`.

## Path Parity Handoff

`path_parity_report.json` is ready for E7/conformance-frontier consumption. It
groups six semantic families and reports two route-disagreement groups:

| Builtin | Semantic family | Reason |
| --- | --- | --- |
| `Array.length` | `array_length_range` | Node oracle executed the source-hash-scoped vector; the matching `source_eval` route is declared expected-unknown. |
| `String.fromCodePoint` | `string_from_code_point_range` | Node oracle executed the source-hash-scoped vector; the matching `source_eval` route is declared expected-unknown. |

Both groups have `failure_count == 0`. E7 should treat these as explicit
frontier limitations, not as confirmed behavior failures.

## Claim-State Decision

No README or claim-to-proof matrix wording should change from this capstone.

- No downgrade is required: there are no confirmed semantic failures and no
  fail-closed bundle result.
- No strengthening is permitted: the evidence is a fixture-level compatibility
  workbench bundle, not a claim-matrix evidence bundle with the mandatory
  claim artifact shape from `docs/CLAIM_LANGUAGE_POLICY.md`.
- A narrower OBSERVED statement is not eligible yet because the capstone still
  contains source-eval `expected_unknown` rows. Future promotion would require
  a replayable engine-route execution artifact with zero undeclared or
  expected-unknown semantic rows, plus an explicit matrix row or existing row
  whose allowed state permits the wording.

The current claim language therefore remains unchanged.

## Commands Run

Gate and replay:

```bash
SEMANTIC_FIDELITY_NOW_UTC=2030-01-01T00:00:00Z SEMANTIC_FIDELITY_SUITE=scripts/testdata/semantic_fidelity_workbench/rangeerror_tointeger_suite.json scripts/run_semantic_fidelity_workbench.sh ci artifacts/semantic_fidelity_workbench_gate/bd-mihky-10-capstone-20300101T000000Z
scripts/e2e/semantic_fidelity_workbench_replay.sh artifacts/semantic_fidelity_workbench_gate/bd-mihky-10-capstone-20300101T000000Z
```

Bundle JSON/JSONL validation:

```bash
jq empty artifacts/semantic_fidelity_workbench_gate/bd-mihky-10-capstone-20300101T000000Z/run_manifest.json artifacts/semantic_fidelity_workbench_gate/bd-mihky-10-capstone-20300101T000000Z/events.jsonl artifacts/semantic_fidelity_workbench_gate/bd-mihky-10-capstone-20300101T000000Z/vector_results.jsonl artifacts/semantic_fidelity_workbench_gate/bd-mihky-10-capstone-20300101T000000Z/path_parity_report.json artifacts/semantic_fidelity_workbench_gate/bd-mihky-10-capstone-20300101T000000Z/auto_triage_report.json
```

Graph checks:

```bash
bv --robot-insights
br dep cycles --json
timeout 120 br dep --no-auto-import --no-auto-flush cycles --json
```

`bv --robot-insights` reported `advanced_insights.cycle_break.cycle_count == 0`.
The unbounded `br dep cycles --json` run produced no output after four minutes
and was interrupted. The bounded no-auto-import/no-auto-flush form exited
`124` after 120 seconds with no output. Treat that as a tracker-tool no-verdict,
not as semantic-fidelity evidence.

No Cargo, build, or Rust test command was run for this capstone.
