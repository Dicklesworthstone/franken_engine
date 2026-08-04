# Semantic Fidelity Frontier Subset Report

Scope: `semantic_fidelity_subset`
Claim policy: `no_claim_promotion`
Source bundle: `artifacts/semantic_fidelity_workbench_gate/bd-mihky-10-capstone-20300101T000000Z`
Source suite: `semfid-suite-rangeerror-tointeger-v1`
Rows: 13

This report is scoped evidence for the semantic-fidelity subset only. It is not full E7 coverage, not a Test262 coverage percentage, and not claim-to-proof matrix promotion evidence.

## Scope State Counts

| Scope state | Rows |
| --- | --- |
| accepted_external_oracle | 11 |
| mismatch | 0 |
| unsupported | 0 |
| expected_unknown | 0 |
| malformed | 0 |
| declared_non_execution | 2 |
| degraded | 0 |

## Coverage Counting

| Coverage class | Rows |
| --- | --- |
| eligible_subset_row | 11 |
| non_passing_scoped_evidence | 2 |
| fail_closed | 0 |

## Clusters

| Cluster | Semantic family | Route kinds | Oracle modes | States | Rows | Vectors |
| --- | --- | --- | --- | --- | --- | --- |
| semfid-cluster-1cbc95143a81f903 | string_repeat_range | node_oracle | external_oracle | accepted_external_oracle | 1 | semfid-string-repeat-negative-count-range-error |
| semfid-cluster-1f4d4e4d111fec97 | number_digits_range | node_oracle | external_oracle | accepted_external_oracle | 2 | semfid-number-to-exponential-negative-range-error, semfid-number-to-precision-zero-range-error |
| semfid-cluster-5a51e68ad1b55503 | string_index_tointeger | node_oracle | external_oracle | accepted_external_oracle | 1 | semfid-string-at-infinity-index-undefined |
| semfid-cluster-5b464fd002063f26 | array_length_range | source_eval | source_eval_declared | declared_non_execution | 1 | semfid-engine-source-eval-array-length-fractional-expected-unknown |
| semfid-cluster-76196213554a853e | string_repeat_range | node_oracle | external_oracle | accepted_external_oracle | 2 | semfid-string-repeat-fractional-count-tointeger, semfid-string-repeat-nan-count-empty-string |
| semfid-cluster-8187d37eaa13d1fe | array_length_range | node_oracle | external_oracle | accepted_external_oracle | 2 | semfid-array-constructor-negative-length-range-error, semfid-array-length-fractional-assignment-range-error |
| semfid-cluster-8f542cffee183298 | string_from_char_code_touint16 | node_oracle | external_oracle | accepted_external_oracle | 1 | semfid-string-from-char-code-uint16-wrap |
| semfid-cluster-bb972bf1a684bc2b | string_from_code_point_range | node_oracle | external_oracle | accepted_external_oracle | 2 | semfid-string-from-code-point-fractional-range-error, semfid-string-from-code-point-high-range-error |
| semfid-cluster-f0276e2db4042038 | string_from_code_point_range | source_eval | source_eval_declared | declared_non_execution | 1 | semfid-engine-source-eval-string-from-code-point-high-expected-unknown |

## Non-Passing Scoped Evidence

| Vector | Route | State | Reason | Coverage | Related beads |
| --- | --- | --- | --- | --- | --- |
| semfid-engine-source-eval-array-length-fractional-expected-unknown | engine.source-eval.array-length-fractional-assignment | declared_non_execution | engine_route_not_executed_by_runner | non_passing_scoped_evidence | bd-fqlfw.7, bd-mihky, bd-mihky.10, bd-mihky.6 |
| semfid-engine-source-eval-string-from-code-point-high-expected-unknown | engine.source-eval.string-from-code-point-high | declared_non_execution | engine_route_not_executed_by_runner | non_passing_scoped_evidence | bd-fqlfw.7, bd-mihky, bd-mihky.10, bd-mihky.6 |

## Related Beads

- `bd-fqlfw.7`
- `bd-mihky`
- `bd-mihky.10`
- `bd-mihky.6`
- `bd-xulus`

## Claim Hygiene

Rows with `declared_non_execution`, `expected_unknown`, `unsupported`, `degraded`, `mismatch`, or `malformed` state cannot be counted as passing coverage. `accepted_external_oracle` rows are eligible only inside this `semantic_fidelity_subset` report.
