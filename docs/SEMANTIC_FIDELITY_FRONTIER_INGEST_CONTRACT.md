# Semantic Fidelity Frontier Ingest Contract V1

Status: initial contract for `bd-09bea.1`
Machine-readable schema: `docs/semantic_fidelity_frontier_ingest_contract_v1.json`
Source workbench: `bd-mihky`
Consumer surface: `bd-fqlfw.7`

## Purpose

The semantic-fidelity workbench emits scoped evidence for builtin and
error-class behavior. E7 still owns the full conformance frontier and remains
blocked on E2/Test262 oracle inputs, but the workbench output is already useful
as a small, replayable frontier subset.

This contract defines the bridge format from semantic-fidelity bundles into
E7-compatible ingest rows. It is intentionally narrow. It lets future tooling
cluster and report the `bd-mihky` workbench results without claiming full
coverage-frontier, Test262, or Node/Bun denominator status.

## Scope Guard

Every bundle using this contract must declare:

- `schema_version`: exactly
  `franken-engine.semantic-fidelity-frontier-ingest.v1`
- `scope`: exactly `semantic_fidelity_subset`
- `claim_policy`: exactly `no_claim_promotion`

The scope label is part of the contract. A consumer must fail closed if a
bundle omits it, changes it, or tries to present rows as full E7 coverage.

This bridge is allowed to support:

- scoped E7 fixture ingestion
- path-parity handoff from `bd-mihky`
- stable cluster ids for a small semantic-family subset
- operator reports that say what was analyzed and what was not analyzed

This bridge must not support:

- README or claim-to-proof matrix promotion
- full Test262 coverage percentages
- automatic conformance bead filing without the E7 review/dedup path
- treating `expected_unknown`, unsupported, or declared non-execution rows as
  passing coverage

## Required Inputs

A frontier ingest bundle is derived from one semantic-fidelity workbench bundle.
The source bundle must contain:

- `run_manifest.json`
- `vector_results.jsonl`
- `summary.md`

The bridge should also preserve these paths when present:

- `path_parity_report.json`
- `auto_triage_report.json`
- `commands.txt`
- the source fixture suite used by the workbench run

The source bundle path, source suite id, source suite hash, and artifact file
hashes must be recorded in `generated_from`.

The V1 bridge recognizes the semantic families emitted by the initial
workbench suites:

- `array_length_range`
- `catchable_error_object`
- `number_digits_range`
- `number_range_or_radix`
- `receiver_validation`
- `string_from_char_code_touint16`
- `string_from_code_point_range`
- `string_index_tointeger`
- `string_repeat_range`
- `to_integer_or_infinity`
- `unsupported_surface`

## Top-Level Shape

The JSON object contains:

- `schema_version`: contract version
- `scope`: `semantic_fidelity_subset`
- `claim_policy`: `no_claim_promotion`
- `generated_from`: source workbench bundle identity and hashes
- `determinism_policy`: ordering and hash-preimage rules
- `rows`: one or more frontier ingest rows

Rows must be ordered lexicographically by `cluster_id`, then `vector_id`, then
`route.route_id`. A consumer must reject duplicate `row_id` values and duplicate
`cluster_id` plus `vector_id` plus `route.route_id` triples.

## Row Fields

Each row records the smallest unit that E7 can cluster:

- `row_id`: stable row id, normally `semfid-frontier-row-*`
- `cluster_id`: content-addressed cluster id, normally
  `semfid-cluster-*`
- `vector_id`: semantic-fidelity vector id from the workbench
- `semantic_family`: copied from the source vector family
- `source_hash`: source hash in `sha256:<hex>` form
- `route`: route id, route kind, and optional lane/runtime metadata
- `oracle_mode`: how the row should be interpreted as evidence
- `observed_outcome`: normalized observed result
- `expected_outcome`: normalized expected result
- `scope_state`: pass/fail/scoped-evidence state for the bridge
- `unsupported_reason`: null unless the row is unsupported, expected-unknown,
  declared non-execution, degraded, or malformed
- `coverage_counting`: whether the row is eligible subset evidence,
  non-passing scoped evidence, or fail-closed
- `related_bead_ids`: Beads links for source, owning, or follow-up work
- `evidence_paths`: source bundle and artifact paths

## Scope States

The bridge recognizes these states:

| State | Meaning | Coverage counting |
| --- | --- | --- |
| `accepted_external_oracle` | External oracle row passed within the workbench's analyzed scope. | `eligible_subset_row` |
| `declared_non_execution` | Engine/source route was intentionally not executed by the workbench. | `non_passing_scoped_evidence` |
| `expected_unknown` | Expected behavior needs confirmation before becoming a regression guard. | `non_passing_scoped_evidence` |
| `unsupported` | Route or semantic surface is outside the current supported subset. | `non_passing_scoped_evidence` |
| `mismatch` | Observed and expected outcomes disagree. | `fail_closed` |
| `malformed` | Source artifact or row validation failed. | `fail_closed` |
| `degraded` | Evidence exists but a declared dependency or oracle is degraded. | `non_passing_scoped_evidence` or `fail_closed` |

`accepted_external_oracle` is not the same as full conformance pass. It is only
eligible within the `semantic_fidelity_subset` report.

## Cluster ID Determinism

`cluster_id` must be content-addressed from normalized fields, not file order.
The intended preimage is length-prefixed UTF-8 fields ordered lexicographically:

```text
schema_version
scope
semantic_family
route.route_kind
oracle_mode
expected_outcome.kind
expected_outcome.error_class
observed_outcome.kind
observed_outcome.error_class
scope_state
```

Absent optional values are encoded as empty strings. The resulting hash is
rendered as `semfid-cluster-` plus a lowercase hex prefix long enough to be
stable in the generated bundle. A collision within one bundle is
`cluster_id_collision` and must fail closed.

## Fail-Closed Conditions

Consumers must reject the bundle or row with a structured diagnostic when any
of these occur:

- missing source bundle file: `missing_source_artifact`
- malformed source JSON or JSONL: `malformed_source_artifact`
- schema version mismatch: `schema_version_mismatch`
- scope label other than `semantic_fidelity_subset`: `unsupported_scope`
- claim policy other than `no_claim_promotion`: `claim_policy_violation`
- duplicate row identity: `duplicate_row_id`
- duplicate cluster/vector/route triple: `duplicate_frontier_row`
- cluster hash collision: `cluster_id_collision`
- missing or invalid hash: `artifact_hash_mismatch`
- replayed source bundle differs from recorded hashes: `replay_mismatch`
- unsupported or expected-unknown row counted as passing coverage:
  `coverage_counting_violation`

## Minimal Example

```json
{
  "schema_version": "franken-engine.semantic-fidelity-frontier-ingest.v1",
  "scope": "semantic_fidelity_subset",
  "claim_policy": "no_claim_promotion",
  "generated_from": {
    "workbench_schema_version": "franken-engine.semantic-fidelity-vectors.v1",
    "source_bundle_path": "artifacts/semantic_fidelity_workbench_gate/bd-mihky-10-capstone-20300101T000000Z",
    "source_suite_id": "semfid-suite-rangeerror-tointeger-v1",
    "source_suite_sha256": "sha256:e730923d9f91db98d243d3bb554ca4288604b5f9660d71de1ce3b533279c3e77",
    "run_manifest_sha256": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    "vector_results_sha256": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    "summary_sha256": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    "source_bead_ids": [
      "bd-mihky",
      "bd-mihky.10",
      "bd-fqlfw.7"
    ]
  },
  "determinism_policy": {
    "row_ordering": "lexicographic_by_cluster_vector_route",
    "hash_preimage": "length_prefixed_utf8_fields_v1",
    "duplicate_row_policy": "fail_closed"
  },
  "rows": [
    {
      "row_id": "semfid-frontier-row-string-repeat-negative-node",
      "cluster_id": "semfid-cluster-0000000000000000",
      "vector_id": "semfid-string-repeat-negative-count",
      "semantic_family": "string_repeat_range",
      "source_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
      "route": {
        "route_id": "oracle.node.string-repeat",
        "route_kind": "node_oracle",
        "external_runtime": "node"
      },
      "oracle_mode": "external_oracle",
      "observed_outcome": {
        "kind": "js_error",
        "error_class": "RangeError"
      },
      "expected_outcome": {
        "kind": "js_error",
        "error_class": "RangeError"
      },
      "scope_state": "accepted_external_oracle",
      "unsupported_reason": null,
      "coverage_counting": "eligible_subset_row",
      "related_bead_ids": [
        "bd-mihky",
        "bd-8tsdh",
        "bd-fqlfw.7"
      ],
      "evidence_paths": {
        "source_bundle_path": "artifacts/semantic_fidelity_workbench_gate/bd-mihky-10-capstone-20300101T000000Z",
        "run_manifest_path": "artifacts/semantic_fidelity_workbench_gate/bd-mihky-10-capstone-20300101T000000Z/run_manifest.json",
        "vector_results_path": "artifacts/semantic_fidelity_workbench_gate/bd-mihky-10-capstone-20300101T000000Z/vector_results.jsonl",
        "summary_path": "artifacts/semantic_fidelity_workbench_gate/bd-mihky-10-capstone-20300101T000000Z/summary.md"
      }
    }
  ]
}
```

## Validation Notes

`bd-09bea.1` only defines the contract. Transformer, fixture, report, and replay
behavior belongs to the later child beads. If any later child touches Rust
sources or runs Cargo validation, those commands must use RCH-only execution.
