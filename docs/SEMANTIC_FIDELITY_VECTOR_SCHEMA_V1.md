# Semantic Fidelity Vector Schema V1

Status: initial contract for `bd-mihky.2`
Machine-readable schema: `docs/semantic_fidelity_vector_schema_v1.json`
Parent inventory: `docs/SEMANTIC_FIDELITY_WORKBENCH_INVENTORY.md`

## Purpose

Semantic-fidelity vectors are small, route-aware fixtures for builtin and
error-class behavior. They must make the route under test, expected observable
outcome, analyzed scope, content hashes, and follow-up action explicit.

The first users are the `bd-mihky` workbench beads:

- `bd-mihky.3`: runner and artifact bundle
- `bd-mihky.4`: RangeError and ToIntegerOrInfinity seed vectors
- `bd-mihky.5`: route-parity report
- `bd-mihky.7`: regression and e2e coverage

This schema does not make a conformance claim. It defines fixture shape and
fail-closed validation rules.

## Fixture Shape

Each fixture file is a vector suite:

- `schema_version`: exactly `franken-engine.semantic-fidelity-vectors.v1`
- `suite_id`: stable `semfid-suite-*` identifier
- `owning_bead`: Beads issue that owns the suite
- `determinism_policy`: optional but recommended; when present it must use
  lexicographic vector/route ordering, length-prefixed UTF-8 hash preimages,
  and fail-closed duplicate-vector handling
- `vectors`: one or more semantic-fidelity vectors

Each vector must include:

- `vector_id`: stable `semfid-*` identifier
- `semantic_family`: one of the schema enum values, such as
  `string_repeat_range`, `string_from_code_point`, or
  `number_range_or_radix`
- `source`: either inline JS source or a fixture path, with a parse goal
- `route_under_test`: one route object
- `oracle_routes`: zero or more comparison/oracle route objects
- `expectation`: exactly one expected outcome branch
- `analyzed_scope`: claim-safety and support status
- `hashes`: source, route metadata, and expectation hashes
- `provenance`: bead and source references
- `remediation`: reason codes and next action when the vector fails

## Route Kinds

The schema recognizes these route kinds:

| Route kind | Intended use |
| --- | --- |
| `source_eval` | `QuickJsInspiredNativeEngine`, `V8InspiredNativeEngine`, or `HybridRouter` source-string eval |
| `builtin_function_kind` | `BuiltinFunctionKind::*` member-access dispatch |
| `hostcall_builtin` | `builtin:*` capability dispatch and builtin-ID routes |
| `string_intrinsic_table` | generated String.prototype intrinsic-table dispatch |
| `stdlib_reference` | internal `stdlib.rs` reference route |
| `node_oracle` | external Node subprocess oracle evidence |
| `bun_oracle` | external Bun subprocess oracle evidence |
| `test262_context` | clause/context metadata only, not a direct execution route |

External runtimes are oracle subprocesses only; they are never core execution
paths.

## Expectations

`expectation` is a `oneOf` union. A vector must choose exactly one branch:

- `normal`: exact or normalized normal value
- `js_error`: expected JS error class, optional message fragments, optional
  catchability flag
- `unsupported`: intentionally unsupported route or surface
- `degraded`: external oracle or artifact degraded but still explainable
- `expected_unknown`: candidate vector whose expected result must be verified
  before it can become a regression guard

Ambiguous expectations are invalid. A validator must fail closed when multiple
branches are present, no branch is present, or required branch fields are
missing.

## Determinism and Hashing

The schema requires three hashes per vector:

- `source_sha256`
- `route_metadata_sha256`
- `expectation_sha256`

Hash values use the `sha256:<64 lowercase hex>` form.

The implementation for `bd-mihky.3` should compute hashes from
length-prefixed UTF-8 fields. The intended preimage shape is:

```text
field_count:u32
field_name_len:u32 field_name:utf8 field_value_len:u64 field_value:utf8
...
```

Fields must be ordered lexicographically by field name, and vector results
must be ordered lexicographically by `vector_id` then `route_id`. Do not use
HashMap iteration order for any emitted artifact.

## Validator Rules

JSON Schema validation covers required fields, closed objects, enum values,
hash syntax, route shape, and one-expectation-only structure.

The runner validator must additionally enforce:

- duplicate `vector_id` is `duplicate_vector_id` and fail-closed
- duplicate `route_id` within one vector is `malformed_vector`
- an external oracle route without an available runtime is
  `external_oracle_unavailable` with `surface_degraded` or `fail_closed`
- `expected_unknown` cannot be used as a passing regression guard
- route disagreement emits `route_disagreement`, not a generic failure
- missing or mismatched fixture file hashes emit `fixture_file_hash_mismatch`
- any unsupported route must carry `unsupported_route`
- unknown or missing source hashes emit `source_hash_mismatch`

## Reason Codes

The schema vocabulary is intentionally small:

- `ambiguous_expectation`
- `duplicate_vector_id`
- `expected_error_class_mismatch`
- `expected_value_mismatch`
- `external_oracle_unavailable`
- `fixture_file_hash_mismatch`
- `incomplete_artifact`
- `malformed_vector`
- `missing_oracle`
- `nondeterministic_output`
- `route_disagreement`
- `source_hash_mismatch`
- `unsupported_route`

These codes are suitable for bundle-doctor style reports and for the
auto-triage bead (`bd-mihky.8`).

## Minimal Example

```json
{
  "schema_version": "franken-engine.semantic-fidelity-vectors.v1",
  "suite_id": "semfid-suite-rangeerror-seed",
  "owning_bead": "bd-mihky.4",
  "determinism_policy": {
    "ordering": "lexicographic_by_vector_id_then_route_id",
    "hash_preimage": "length_prefixed_utf8_fields_v1",
    "duplicate_vector_id_policy": "fail_closed"
  },
  "vectors": [
    {
      "vector_id": "semfid-string-repeat-negative-count",
      "semantic_family": "string_repeat_range",
      "description": "String.prototype.repeat negative count must throw RangeError.",
      "source": {
        "kind": "inline_source",
        "parse_goal": "script",
        "inline_source": "let s = \"x\"; s.repeat(-1);"
      },
      "route_under_test": {
        "route_id": "eval.quickjs.string-repeat",
        "route_kind": "source_eval",
        "engine_lane": "quickjs_inspired"
      },
      "oracle_routes": [
        {
          "route_id": "oracle.node.string-repeat",
          "route_kind": "node_oracle",
          "external_runtime": "node"
        }
      ],
      "expectation": {
        "kind": "js_error",
        "error_class": "RangeError",
        "message_contains": [
          "non-negative"
        ],
        "catchable": true
      },
      "analyzed_scope": {
        "scope_status": "analyzed",
        "claim_policy": "regression_guard_only",
        "notes": "Seeded from bd-8tsdh and inventory bd-mihky.1."
      },
      "hashes": {
        "source_sha256": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "route_metadata_sha256": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "expectation_sha256": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
      },
      "provenance": {
        "bead_refs": [
          "bd-8tsdh",
          "bd-mihky.1"
        ],
        "source_refs": [
          {
            "path": "crates/franken-engine/tests/string_prototype_methods_part2_bd9a8cz1.rs",
            "symbol": "repeat_negative_count_is_range_error_bd_8tsdh"
          }
        ]
      },
      "remediation": {
        "failure_reason_codes": [
          "expected_error_class_mismatch",
          "route_disagreement"
        ],
        "existing_bead_refs": [
          "bd-xulus"
        ],
        "suggested_next_action": "link_existing_bead"
      }
    }
  ]
}
```

The zero hashes in the example are placeholders for documentation only. Real
fixtures must use actual content hashes.

## Operator Verification

```bash
jq empty docs/semantic_fidelity_vector_schema_v1.json

git diff --check -- \
  docs/SEMANTIC_FIDELITY_VECTOR_SCHEMA_V1.md \
  docs/semantic_fidelity_vector_schema_v1.json
```

Cargo-heavy validation for future implementation beads must run through `rch`.
